package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/K0NGR3SS/ghostweights/internal/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

var suspiciousProcesses = []string{
	"ollama",
	"streamlit",
	"vllm",
	"text-generation-launcher",
	"ray start",
	"jupyter-lab",
}

func (s *Scanner) DeepScan(ctx context.Context, instanceIDs []string) ([]models.Finding, error) {
	var findings []models.Finding
	if len(instanceIDs) == 0 {
		return findings, nil
	}

	fmt.Printf(" [>] Starting Deep Scan (SSM) on %d instances...\n", len(instanceIDs))

	pattern := strings.Join(suspiciousProcesses, "|")
	cmd := "ps -eo args | grep -E '" + pattern + "' | grep -v grep || true"

	out, err := s.Client.SSM.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  instanceIDs,
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters: map[string][]string{
			"commands": {cmd},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send SSM command: %w", err)
	}
	if out.Command == nil || out.Command.CommandId == nil {
		return nil, fmt.Errorf("ssm SendCommand returned empty command id")
	}

	commandID := *out.Command.CommandId

	for _, instanceID := range instanceIDs {
		stdout, status, err := s.waitCommandOutput(ctx, commandID, instanceID, 35*time.Second)
		if err != nil {
			continue
		}

		if status == types.CommandInvocationStatusSuccess && strings.TrimSpace(stdout) != "" {
			foundProcess := strings.TrimSpace(stdout)

			findings = append(findings, models.Finding{
				InstanceID:  instanceID,
				Region:      s.Client.Region,
				Risk:        models.RiskMedium,
				Service:     "Hidden AI Process",
				Description: "Found active AI/ML process via SSM",
				Evidence:    fmt.Sprintf("Process: %s", truncate(foundProcess, 120)),
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

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
