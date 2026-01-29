package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/K0NGR3SS/ghostweights/internal/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pterm/pterm"
)

var aiKeywords = []string{
	"model", "models", "ml", "ai", "dataset", "datasets",
	"rag", "embeddings", "vectors", "training", "inference",
	"llm", "huggingface", "ollama", "weights", "checkpoint",
}

func (s *Scanner) ScanS3Buckets(ctx context.Context, spinner *pterm.SpinnerPrinter) ([]models.Finding, error) {
	var findings []models.Finding

	spinner.UpdateText("Scanning S3 buckets for AI artifacts...")
	s3Client := s3.NewFromConfig(s.Client.Config)
	listResult, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 buckets: %w", err)
	}

	spinner.UpdateText(fmt.Sprintf("Analyzing %d S3 buckets...", len(listResult.Buckets)))

	for idx, bucket := range listResult.Buckets {
		bucketName := aws.ToString(bucket.Name)
		
		spinner.UpdateText(fmt.Sprintf("Checking bucket %s (%d/%d)...", bucketName, idx+1, len(listResult.Buckets)))

		isAIRelated := false
		for _, keyword := range aiKeywords {
			if strings.Contains(strings.ToLower(bucketName), keyword) {
				isAIRelated = true
				break
			}
		}

		if !isAIRelated {
			continue
		}

		locationResult, err := s3Client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			continue
		}

		bucketRegion := string(locationResult.LocationConstraint)
		if bucketRegion == "" {
			bucketRegion = "us-east-1"
		}

		aclResult, err := s3Client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: aws.String(bucketName),
		})

		isPublic := false
		if err == nil {
			for _, grant := range aclResult.Grants {
				if grant.Grantee != nil && grant.Grantee.URI != nil {
					uri := *grant.Grantee.URI
					if strings.Contains(uri, "AllUsers") || strings.Contains(uri, "AuthenticatedUsers") {
						isPublic = true
						break
					}
				}
			}
		}
		policyResult, err := s3Client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		if err == nil && policyResult.Policy != nil {
			policyStr := aws.ToString(policyResult.Policy)
			if strings.Contains(policyStr, `"Principal":"*"`) || strings.Contains(policyStr, `"Principal":{"AWS":"*"}`) {
				isPublic = true
			}
		}

		encryptionResult, err := s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: aws.String(bucketName),
		})
		isEncrypted := err == nil && len(encryptionResult.ServerSideEncryptionConfiguration.Rules) > 0
		listObjResult, err := s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  aws.String(bucketName),
			MaxKeys: aws.Int32(100),
		})

		var modelFiles []string
		var totalSize int64
		if err == nil {
			for _, obj := range listObjResult.Contents {
				key := aws.ToString(obj.Key)
				totalSize += aws.ToInt64(obj.Size)

				if strings.HasSuffix(key, ".safetensors") ||
					strings.HasSuffix(key, ".gguf") ||
					strings.HasSuffix(key, ".bin") ||
					strings.HasSuffix(key, ".pt") ||
					strings.HasSuffix(key, ".pth") ||
					strings.HasSuffix(key, ".h5") ||
					strings.HasSuffix(key, ".pb") {
					modelFiles = append(modelFiles, key)
				}
			}
		}

		risk := models.RiskMedium
		if isPublic {
			risk = models.RiskCritical
		} else if !isEncrypted {
			risk = models.RiskHigh
		}

		desc := fmt.Sprintf("AI-related bucket")
		if len(modelFiles) > 0 {
			desc = fmt.Sprintf("Contains %d model files", len(modelFiles))
		}
		if isPublic {
			desc += " (PUBLIC ACCESS)"
		}
		if !isEncrypted {
			desc += " (UNENCRYPTED)"
		}

		evidence := fmt.Sprintf("Bucket: %s, Region: %s, Size: %.2f MB", 
			bucketName, bucketRegion, float64(totalSize)/(1024*1024))
		
		if len(modelFiles) > 0 {
			evidence += fmt.Sprintf(", Files: %s", strings.Join(modelFiles[:min(3, len(modelFiles))], ", "))
		}

		findings = append(findings, models.Finding{
			InstanceID:  bucketName,
			Region:      bucketRegion,
			Risk:        risk,
			Service:     "S3 Bucket",
			Description: desc,
			Evidence:    evidence,
		})
	}

	return findings, nil
}
