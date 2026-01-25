package scanner

import (
	"context"
	"fmt"
	"log"

	client "github.com/K0NGR3SS/ghostweights/internal/aws"
	"github.com/K0NGR3SS/ghostweights/internal/models"
	"github.com/K0NGR3SS/ghostweights/internal/ui"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/pterm/pterm"
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

func (s *Scanner) Scan(ctx context.Context, spinner *pterm.SpinnerPrinter) ([]models.Finding, error) {
	var findings []models.Finding

	ui.UpdateSpinner(spinner, fmt.Sprintf("Fetching EC2 instances in %s...", s.Client.Region))

	result, err := s.Client.EC2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %w", err)
	}

	seen := map[string]struct{}{}

	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			instanceID := aws.ToString(instance.InstanceId)
			if instanceID == "" {
				continue
			}

			ui.UpdateSpinner(spinner, fmt.Sprintf("Scanning network rules for %s...", instanceID))

			name := getNameTag(instance.Tags)
			publicIP := getPublicIP(instance)
			privateIP := getPrivateIP(instance)

			for _, sg := range instance.SecurityGroups {
				groupID := aws.ToString(sg.GroupId)
				if groupID == "" {
					continue
				}

				sgRules, err := s.getSecurityGroupRules(ctx, groupID)
				if err != nil {
					log.Printf("Failed to get rules for SG %s: %v", groupID, err)
					continue
				}

				for _, rule := range sgRules {
					if !isPubliclyExposed(rule) {
						continue
					}
					if !isTCPOrAll(rule) {
						continue
					}

					for port, serviceName := range aiPorts {
						if ruleCoversPort(rule, port) {
							key := fmt.Sprintf("%s:%d:%s", instanceID, port, serviceName)
							if _, ok := seen[key]; ok {
								continue
							}
							seen[key] = struct{}{}

							findings = append(findings, models.Finding{
								InstanceID:  instanceID,
								Region:      s.Client.Region,
								PublicIP:    publicIP,
								PrivateIP:   privateIP,
								NameTag:     name,
								Risk:        models.RiskHigh,
								Service:     serviceName,
								Port:        port,
								Description: fmt.Sprintf("Exposed %s port", serviceName),
								Evidence:    fmt.Sprintf("Port %d open to 0.0.0.0/0 or ::/0 in SG %s", port, groupID),
							})
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
			ssmFindings, err := s.DeepScan(ctx, allInstanceIDs, spinner)
			if err == nil {
				findings = append(findings, ssmFindings...)
			} else {
				ui.UpdateSpinner(spinner, fmt.Sprintf("SSM Scan skipped: %v", err))
			}
		}
	}

	return findings, nil
}

func (s *Scanner) getSecurityGroupRules(ctx context.Context, groupID string) ([]types.IpPermission, error) {
	res, err := s.Client.EC2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{groupID},
    })
	if err != nil {
		return nil, err
	}
	if len(res.SecurityGroups) == 0 {
		return nil, nil
	}
	return res.SecurityGroups[0].IpPermissions, nil
}

func isPubliclyExposed(rule types.IpPermission) bool {
	for _, ipRange := range rule.IpRanges {
		if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
			return true
		}
	}
	for _, ip6Range := range rule.Ipv6Ranges {
		if aws.ToString(ip6Range.CidrIpv6) == "::/0" {
			return true
		}
	}
	return false
}

func isTCPOrAll(rule types.IpPermission) bool {
	proto := aws.ToString(rule.IpProtocol)
	return proto == "" || proto == "tcp" || proto == "-1"
}

func ruleCoversPort(rule types.IpPermission, port int32) bool {
	if rule.FromPort == nil || rule.ToPort == nil {
		return true
	}
	return port >= *rule.FromPort && port <= *rule.ToPort
}

func getNameTag(tags []types.Tag) string {
	for _, t := range tags {
		if aws.ToString(t.Key) == "Name" && t.Value != nil {
			return *t.Value
		}
	}
	return "Unknown"
}

func getPublicIP(instance types.Instance) string {
	if instance.PublicIpAddress != nil {
		return *instance.PublicIpAddress
	}
	return "N/A"
}

func getPrivateIP(instance types.Instance) string {
	if instance.PrivateIpAddress != nil {
		return *instance.PrivateIpAddress
	}
	return "N/A"
}
