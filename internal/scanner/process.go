package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/K0NGR3SS/ghostweights/internal/models"
	"github.com/K0NGR3SS/ghostweights/internal/ui"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/pterm/pterm"
)

var suspiciousProcesses = []string{
	"ollama", "streamlit", "vllm", "text-generation",
	"ray", "jupyter", "python", "uvicorn", "gunicorn",
	"llama-cpp", "koboldcpp", "oobabooga", "localai",
}

func (s *Scanner) DeepScan(ctx context.Context, instanceIDs []string, spinner *pterm.SpinnerPrinter) ([]models.Finding, error) {
	var findings []models.Finding
	if len(instanceIDs) == 0 {
		return findings, nil
	}

	ui.UpdateSpinner(spinner, fmt.Sprintf("Starting Deep AI Scan (SSM) on %d instances...", len(instanceIDs)))
	cmdScript := `
#!/bin/bash
set -e

echo "OS|$(uname -s)"

# 1. Find suspicious processes with full command lines
for proc in ` + strings.Join(suspiciousProcesses, " ") + `; do
	pids=$(pgrep -f "$proc" 2>/dev/null || true)
	for pid in $pids; do
		cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' || true)
		if [ ! -z "$cmdline" ]; then
			echo "PROCESS|$pid|$cmdline"
		fi
	done
done

# 2. Check GPU presence
if command -v nvidia-smi &> /dev/null; then
	model=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -n 1 || echo "Unknown")
	echo "GPU|$model"
fi

# 3. Look for AI model files on disk (exclude Docker and node_modules)
find /home /root /opt /var \
	-path "*/docker/*" -prune -o \
	-path "*/node_modules/*" -prune -o \
	-path "*/.git/*" -prune -o \
	\( -name "*.safetensors" -o -name "*.gguf" -o -name "*.bin" -o -name "*.pt" -o -name "*.pth" \) \
	-size +10M \
	-print 2>/dev/null | head -n 10 | while read file; do
		echo "MODEL_FILE|$file"
done

# 4. Check for Python AI packages
if command -v pip &> /dev/null; then
	pip list 2>/dev/null | grep -iE 'torch|tensorflow|transformers|langchain|llama|vllm|ray' | while read line; do
		echo "PIP_PACKAGE|$line"
	done
fi

# 5. Check for exposed Jupyter without token
if command -v jupyter &> /dev/null; then
	jupyter notebook list 2>/dev/null | grep -v token | grep http | while read line; do
		echo "JUPYTER_NOAUTH|$line"
	done
fi

# 6. Look for API keys in environment
env | grep -iE 'api_key|openai|anthropic|huggingface|together' | while read line; do
	echo "API_KEY|$line"
done

# 7. Check for common AI directories
for dir in /opt/models /home/*/models ~/.cache/huggingface ~/.cache/ollama; do
	if [ -d "$dir" ]; then
		size=$(du -sh "$dir" 2>/dev/null | cut -f1 || echo "Unknown")
		echo "AI_DIR|$dir|$size"
	fi
done
`

	out, err := s.Client.SSM.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  instanceIDs,
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters: map[string][]string{
			"commands": {cmdScript},
		},
		TimeoutSeconds: aws.Int32(60),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send SSM command: %w", err)
	}

	if out.Command == nil || out.Command.CommandId == nil {
		return nil, fmt.Errorf("ssm SendCommand returned empty command id")
	}
	commandID := *out.Command.CommandId

	successCount := 0
	failCount := 0

	for i, instanceID := range instanceIDs {
		ui.UpdateSpinner(spinner, fmt.Sprintf("Deep Scanning %s (%d/%d)...", instanceID, i+1, len(instanceIDs)))

		stdout, status, err := s.waitCommandOutput(ctx, commandID, instanceID, 30*time.Second)
		if err != nil {
			failCount++
			pterm.Warning.Printf("SSM failed on %s: %v\n", instanceID, err)
			findings = append(findings, models.Finding{
				InstanceID:  instanceID,
				Region:      s.Client.Region,
				Risk:        models.RiskLow,
				Service:     "SSM Agent",
				Description: "Deep scan failed - SSM may not be installed",
				Evidence:    fmt.Sprintf("Error: %v", err),
			})
			continue
		}
		
		if status != types.CommandInvocationStatusSuccess {
			failCount++
			pterm.Warning.Printf("SSM command failed on %s with status: %s\n", instanceID, status)
			continue
		}
		
		successCount++

		lines := strings.Split(stdout, "\n")
		var gpuModel string
		var osType string
		var foundAIProcs []string
		var modelFiles []string
		var aiPackages []string
		var apiKeys []string
		var aiDirs []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			
			if strings.HasPrefix(line, "OS|") {
				osType = strings.TrimPrefix(line, "OS|")
			} else if strings.HasPrefix(line, "GPU|") {
				gpuModel = strings.TrimPrefix(line, "GPU|")
			} else if strings.HasPrefix(line, "PROCESS|") {
				parts := strings.SplitN(line, "|", 3)
				if len(parts) == 3 {
					cmdArgs := parts[2]

					if !strings.Contains(cmdArgs, "ssm-agent") && 
					   !strings.Contains(cmdArgs, "pgrep") && 
					   !strings.Contains(cmdArgs, "cfn-hup") &&
					   !strings.Contains(cmdArgs, "/bin/sh") {
						foundAIProcs = append(foundAIProcs, cmdArgs)
					}
				}
			} else if strings.HasPrefix(line, "MODEL_FILE|") {
				modelFiles = append(modelFiles, strings.TrimPrefix(line, "MODEL_FILE|"))
			} else if strings.HasPrefix(line, "PIP_PACKAGE|") {
				aiPackages = append(aiPackages, strings.TrimPrefix(line, "PIP_PACKAGE|"))
			} else if strings.HasPrefix(line, "API_KEY|") {
				apiKeys = append(apiKeys, strings.TrimPrefix(line, "API_KEY|"))
			} else if strings.HasPrefix(line, "AI_DIR|") {
				aiDirs = append(aiDirs, strings.TrimPrefix(line, "AI_DIR|"))
			} else if strings.HasPrefix(line, "JUPYTER_NOAUTH|") {
				findings = append(findings, models.Finding{
					InstanceID:  instanceID,
					Region:      s.Client.Region,
					Risk:        models.RiskCritical,
					Service:     "Jupyter Notebook",
					Description: "Jupyter running without authentication",
					Evidence:    strings.TrimPrefix(line, "JUPYTER_NOAUTH|"),
				})
			}
		}

		if osType != "" && osType != "Linux" {
			findings = append(findings, models.Finding{
				InstanceID:  instanceID,
				Region:      s.Client.Region,
				Risk:        models.RiskLow,
				Service:     "OS Compatibility",
				Description: fmt.Sprintf("Instance running %s (deep scan limited)", osType),
				Evidence:    "Deep scan optimized for Linux only",
			})
		}
		if gpuModel != "" && gpuModel != "Unknown" {
			findings = append(findings, models.Finding{
				InstanceID:  instanceID,
				Region:      s.Client.Region,
				Risk:        models.RiskMedium,
				Service:     "GPU Detected",
				Description: fmt.Sprintf("NVIDIA GPU present: %s", gpuModel),
				Evidence:    "Potential AI/ML workload infrastructure",
			})
		}

		if len(modelFiles) > 0 {
			findings = append(findings, models.Finding{
				InstanceID:  instanceID,
				Region:      s.Client.Region,
				Risk:        models.RiskHigh,
				Service:     "AI Model Files",
				Description: fmt.Sprintf("Found %d model files on disk", len(modelFiles)),
				Evidence:    fmt.Sprintf("Files: %s", strings.Join(modelFiles[:min(3, len(modelFiles))], ", ")),
			})
		}

		if len(aiPackages) > 0 {
			findings = append(findings, models.Finding{
				InstanceID:  instanceID,
				Region:      s.Client.Region,
				Risk:        models.RiskMedium,
				Service:     "AI Python Packages",
				Description: fmt.Sprintf("Found %d AI/ML packages installed", len(aiPackages)),
				Evidence:    strings.Join(aiPackages[:min(3, len(aiPackages))], ", "),
			})
		}

		if len(apiKeys) > 0 {
			for _, key := range apiKeys {
				findings = append(findings, models.Finding{
					InstanceID:  instanceID,
					Region:      s.Client.Region,
					Risk:        models.RiskCritical,
					Service:     "Exposed API Key",
					Description: "API key found in environment variables",
					Evidence:    maskAPIKey(key),
				})
			}
		}

		if len(aiDirs) > 0 {
			findings = append(findings, models.Finding{
				InstanceID:  instanceID,
				Region:      s.Client.Region,
				Risk:        models.RiskMedium,
				Service:     "AI Model Cache",
				Description: fmt.Sprintf("Found %d AI model directories", len(aiDirs)),
				Evidence:    strings.Join(aiDirs, ", "),
			})
		}

		for _, procCmd := range foundAIProcs {
			risk := models.RiskMedium
			serviceName := "Suspicious Process"
			desc := "Potential AI workload"

			if strings.Contains(procCmd, "vllm") {
				serviceName = "vLLM Inference Server"
				risk = models.RiskHigh
				modelName := extractArgValue(procCmd, "--model")
				if modelName == "" {
					fields := strings.Fields(procCmd)
					for i, f := range fields {
						if f == "serve" && i+1 < len(fields) && !strings.HasPrefix(fields[i+1], "-") {
							modelName = fields[i+1]
							break
						}
					}
				}
				if modelName != "" {
					desc = fmt.Sprintf("Serving model: %s", modelName)
				} else {
					desc = "Serving unknown model via vLLM"
				}
			} else if strings.Contains(procCmd, "ollama serve") {
				serviceName = "Ollama Service"
				risk = models.RiskCritical
				desc = "Active Ollama API"
			} else if strings.Contains(procCmd, "llama") || strings.Contains(procCmd, "mistral") {
				serviceName = "LLM Process"
				risk = models.RiskHigh
				desc = "Found model name in process args"
			} else if strings.Contains(procCmd, "streamlit run") {
				serviceName = "Streamlit App"
				risk = models.RiskHigh
				desc = "Interactive ML dashboard running"
			} else if strings.Contains(procCmd, "ray start") {
				serviceName = "Ray Cluster"
				risk = models.RiskHigh
				desc = "Distributed computing framework active"
			}

			if gpuModel != "" {
				desc += fmt.Sprintf(" on GPU (%s)", gpuModel)
			}

			findings = append(findings, models.Finding{
				InstanceID:  instanceID,
				Region:      s.Client.Region,
				Risk:        risk,
				Service:     serviceName,
				Description: desc,
				Evidence:    fmt.Sprintf("Cmd: %s", truncate(procCmd, 120)),
			})
		}
	}

	pterm.Info.Printf("SSM Deep Scan: %d succeeded, %d failed\n", successCount, failCount)

	return findings, nil
}

func (s *Scanner) waitCommandOutput(ctx context.Context, commandID, instanceID string, timeout time.Duration) (string, types.CommandInvocationStatus, error) {
	deadline := time.Now().Add(timeout)

	for {
		if time.Now().After(deadline) {
			return "", types.CommandInvocationStatusTimedOut, fmt.Errorf("ssm invocation timed out for %s", instanceID)
		}

		res, err := s.Client.SSM.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(commandID),
			InstanceId: aws.String(instanceID),
			PluginName: aws.String("aws:runShellScript"),
		})
		if err != nil {
			select {
			case <-ctx.Done():
				return "", types.CommandInvocationStatusCancelled, ctx.Err()
			case <-time.After(1 * time.Second):
				continue
			}
		}

		switch res.Status {
		case types.CommandInvocationStatusPending,
			types.CommandInvocationStatusInProgress,
			types.CommandInvocationStatusDelayed:
			select {
			case <-ctx.Done():
				return "", types.CommandInvocationStatusCancelled, ctx.Err()
			case <-time.After(1 * time.Second):
				continue
			}
		default:
			return aws.ToString(res.StandardOutputContent), res.Status, nil
		}
	}
}

func extractArgValue(cmdLine, flag string) string {
	fields := strings.Fields(cmdLine)
	for i, f := range fields {
		if (f == flag) && i+1 < len(fields) {
			return fields[i+1]
		}
		if strings.HasPrefix(f, flag+"=") {
			return strings.TrimPrefix(f, flag+"=")
		}
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func maskAPIKey(keyLine string) string {
	parts := strings.SplitN(keyLine, "=", 2)
	if len(parts) == 2 {
		key := parts[1]
		if len(key) > 8 {
			return fmt.Sprintf("%s=%s***%s", parts[0], key[:4], key[len(key)-4:])
		}
	}
	return keyLine
}