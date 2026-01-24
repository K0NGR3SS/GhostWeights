package scanner

import (
	"context"
	"fmt"

	"github.com/K0NGR3SS/ghostweights/internal/aws"
	"github.com/K0NGR3SS/ghostweights/internal/models"
)

type Scanner struct {
	Client *aws.Client
}

func New(client *aws.Client) *Scanner {
	return &Scanner{Client: client}
}

func (s *Scanner) Scan(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	fmt.Printf(" [>] Scanning EC2 instances in %s...\n", s.Client.Region)
	
	// TODO: Implement actual EC2 logic here in the next step

	return findings, nil
}
