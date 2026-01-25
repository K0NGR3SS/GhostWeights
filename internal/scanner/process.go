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
}

func (s *Scanner) DeepScan(ctx context.Context, instanceIDs []string, spinner *pterm.SpinnerPrinter) ([]models.Finding, error) {
	var findings []models.Finding
	if len(instanceIDs) == 0 {
		return findings, nil
	}

	ui.UpdateSpinner(spinner, fmt.Sprintf("Starting Deep AI Scan (SSM) on %d instances...", len(instanceIDs)))

	cmdScript := `
	# 1. Find suspicious processes and print cmdline
	for proc in ` + strings.Join(suspiciousProcesses, " ") + `; do
		pids=$(pgrep -f "$proc")
		for pid in $pids; do
			# Get full command line (null-separated -> space-separated)
			cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
			if [ ! -z "$cmdline" ]; then
				echo "PROCESS|$pid|$cmdline"
			fi
		done
	done

	# 2. Check GPU
	if command -v nvidia-smi &> /dev/null; then
		model=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -n 1)
		echo "GPU|$model"
	fi
	`

	out, err := s.Client.SSM.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  instanceIDs,
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters: map[string][]string{
			"commands": {cmdScript},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send SSM command: %w", err)
	}

	if out.Command == nil || out.Command.CommandId == nil {
		return nil, fmt.Errorf("ssm SendCommand returned empty command id")
	}
	commandID := *out.Command.CommandId

	for i, instanceID := range instanceIDs {
		ui.UpdateSpinner(spinner, fmt.Sprintf("Deep Scanning %s (%d/%d)...", instanceID, i+1, len(instanceIDs)))

		stdout, status, err := s.waitCommandOutput(ctx, commandID, instanceID, 15*time.Second)
		if err != nil || status != types.CommandInvocationStatusSuccess {
			continue
		}

		lines := strings.Split(stdout, "\n")
		var gpuModel string
		var foundAIProcs []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "GPU|") {
				gpuModel = strings.TrimPrefix(line, "GPU|")
			} else if strings.HasPrefix(line, "PROCESS|") {
				parts := strings.SplitN(line, "|", 3)
				if len(parts) == 3 {
					cmdArgs := parts[2]
					if !strings.Contains(cmdArgs, "ssm-agent") && 
					   !strings.Contains(cmdArgs, "pgrep") && 
					   !strings.Contains(cmdArgs, "cfn-hup") {
						foundAIProcs = append(foundAIProcs, cmdArgs)
					}
				}
			}
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
				desc = "Active Ollama API"
			} else if strings.Contains(procCmd, "llama") || strings.Contains(procCmd, "mistral") {
				serviceName = "LLM Process"
				desc = "Found model name in process args"
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
			case <-time.After(800 * time.Millisecond):
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
			case <-time.After(800 * time.Millisecond):
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
