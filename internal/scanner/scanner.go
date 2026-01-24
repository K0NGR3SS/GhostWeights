package scanner

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	client "github.com/K0NGR3SS/ghostweights/internal/aws"
	"github.com/K0NGR3SS/ghostweights/internal/models"
)

var aiPorts = map[int32]string{
	11434: "Ollama API",
	8501:  "Streamlit App",
	7860:  "Gradio (HuggingFace)",
	8000:  "vLLM / FastChat",
	8265:  "Ray Dashboard",
	8888:  "Jupyter Notebook",
	5000:  "MLflow / Flask",
}

type Scanner struct {
	Client *client.Client
	Deep   bool
}

func New(c *client.Client, deep bool) *Scanner {
	return &Scanner{Client: c, Deep: deep}
}

func (s *Scanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	fmt.Printf(" [>] Fetching EC2 instances in %s...\n", s.Client.Region)

	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	}

	result, err := s.Client.EC2.DescribeInstances(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %w", err)
	}

	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			name := "Unknown"
			for _, t := range instance.Tags {
				if *t.Key == "Name" {
					name = *t.Value
					break
				}
			}

			for _, sg := range instance.SecurityGroups {
				sgRules, err := s.getSecurityGroupRules(ctx, *sg.GroupId)
				if err != nil {
					log.Printf("Failed to get rules for SG %s: %v", *sg.GroupId, err)
					continue
				}

				for _, rule := range sgRules {
					if rule.FromPort == nil {
						continue
					}
					
					port := *rule.FromPort

					if serviceName, isAI := aiPorts[port]; isAI {
						if isPubliclyExposed(rule) {
							f := models.Finding{
								InstanceID:  *instance.InstanceId,
								Region:      s.Client.Region,
								PublicIP:    getPublicIP(instance),
								PrivateIP:   *instance.PrivateIpAddress,
								NameTag:     name,
								Risk:        models.RiskHigh,
								Service:     serviceName,
								Port:        port,
								Description: fmt.Sprintf("Exposed %s port", serviceName),
								Evidence:    fmt.Sprintf("Port %d open to 0.0.0.0/0 in SG %s", port, *sg.GroupId),
							}
							findings = append(findings, f)
						}
					}
				}
			}
		}
	}

	if s.Deep {
		var allInstanceIDs []string
		for _, r := range result.Reservations {
			for _, i := range r.Instances {
				if i.InstanceId != nil {
					allInstanceIDs = append(allInstanceIDs, *i.InstanceId)
				}
			}
		}

		if len(allInstanceIDs) > 0 {
			ssmFindings, err := s.DeepScan(ctx, allInstanceIDs)
			if err == nil {
				findings = append(findings, ssmFindings...)
			} else {
				fmt.Printf(" [!] SSM Scan skipped or failed: %v\n", err)
			}
		}
	}

	return findings, nil
}

func (s *Scanner) getSecurityGroupRules(ctx context.Context, groupID string) ([]types.IpPermission, error) {
	input := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{groupID},
	}
	res, err := s.Client.EC2.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, err
	}
	if len(res.SecurityGroups) > 0 {
		return res.SecurityGroups[0].IpPermissions, nil
	}
	return nil, nil
}

func isPubliclyExposed(rule types.IpPermission) bool {
	for _, ipRange := range rule.IpRanges {
		if *ipRange.CidrIp == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

func getPublicIP(instance types.Instance) string {
	if instance.PublicIpAddress != nil {
		return *instance.PublicIpAddress
	}
	return "N/A"
}