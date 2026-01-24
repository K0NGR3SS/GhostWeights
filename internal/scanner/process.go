package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/K0NGR3SS/ghostweights/internal/models"
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

	cmd := "ps -eo args | grep -E '" + strings.Join(suspiciousProcesses, "|") + "' | grep -v grep"
	
	input := &ssm.SendCommandInput{
		InstanceIds:  instanceIDs,
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters: map[string][]string{
			"commands": {cmd},
		},
	}

	output, err := s.Client.SSM.SendCommand(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to send SSM command: %v", err)
	}

	commandID := output.Command.CommandId
	time.Sleep(2 * time.Second)

	for _, instanceID := range instanceIDs {
		res, err := s.Client.SSM.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  commandID,
			InstanceId: aws.String(instanceID),
		})

		if err != nil {
			continue
		}

		if res.Status == types.CommandInvocationStatusSuccess && len(*res.StandardOutputContent) > 0 {

			foundProcess := strings.TrimSpace(*res.StandardOutputContent)
			
			f := models.Finding{
				InstanceID:  instanceID,
				Region:      s.Client.Region,
				Risk:        models.RiskMedium,
				Service:     "Hidden AI Process",
				Description: fmt.Sprintf("Found active AI process via SSM"),
				Evidence:    fmt.Sprintf("Process: %s", truncate(foundProcess, 50)),
			}
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
