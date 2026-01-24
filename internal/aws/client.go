package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

type Client struct {
	EC2 *ec2.Client
	SSM *ssm.Client
	Region string
}

func NewClient(ctx context.Context, region string) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v", err)
	}

	return &Client{
		EC2: ec2.NewFromConfig(cfg),
		SSM: ssm.NewFromConfig(cfg),
		Region: region,
	}, nil
}
