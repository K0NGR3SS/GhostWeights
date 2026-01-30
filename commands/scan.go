package commands

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/K0NGR3SS/ghostweights/internal/aws"
	"github.com/K0NGR3SS/ghostweights/internal/models"
	"github.com/K0NGR3SS/ghostweights/internal/scanner"
	"github.com/K0NGR3SS/ghostweights/internal/ui"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var validRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "eu-south-1",
	"ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ap-southeast-1", "ap-southeast-2", "ap-east-1",
	"ca-central-1", "sa-east-1", "af-south-1", "me-south-1",
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Start the Shadow AI hunt",
	Long:  `Scans the target AWS region for EC2 instances exposing AI/ML ports (Ollama, Ray, Streamlit).`,
	Run: func(cmd *cobra.Command, args []string) {
		region, _ := cmd.Flags().GetString("region")
		deep, _ := cmd.Flags().GetBool("deep")
		outputFormat, _ := cmd.Flags().GetString("format")
		outputFile, _ := cmd.Flags().GetString("output")
		minRisk, _ := cmd.Flags().GetString("min-risk")
		allRegions, _ := cmd.Flags().GetBool("all-regions")
		excludeIDs, _ := cmd.Flags().GetStringSlice("exclude-ids")

		if outputFormat != "table" && outputFormat != "json" && outputFormat != "csv" {
			pterm.Error.Printf("Invalid format: %s (must be: table, json, or csv)\n", outputFormat)
			os.Exit(1)
		}

		minRiskLevel := parseRiskLevel(minRisk)

		var regionsToScan []string
		if allRegions {
			regionsToScan = validRegions
			pterm.Info.Println("Scanning ALL AWS regions (this may take a while)...")
		} else {
			if region == "" {
				result, _ := pterm.DefaultInteractiveTextInput.
					WithDefaultText("us-east-1").
					Show("Enter AWS Region to scan")

				if result == "" {
					region = "us-east-1"
				} else {
					region = result
				}
			}

			if !isValidRegion(region) {
				pterm.Warning.Printf("Region '%s' may not be valid. Valid regions: %s\n", 
					region, strings.Join(validRegions[:5], ", ")+"...")
				
				confirm, _ := pterm.DefaultInteractiveConfirm.
					WithDefaultText("Continue anyway?").
					WithDefaultValue(false).
					Show()
				
				if !confirm {
					os.Exit(0)
				}
			}

			regionsToScan = []string{region}
		}

		var allFindings []models.Finding

		for _, reg := range regionsToScan {
			findings := scanRegion(reg, deep, excludeIDs)
			allFindings = append(allFindings, findings...)
		}

		filteredFindings := filterByRisk(allFindings, minRiskLevel)

		if outputFile != "" {
			err := writeOutput(filteredFindings, outputFormat, outputFile)
			if err != nil {
				pterm.Error.Printf("Failed to write output: %v\n", err)
				os.Exit(1)
			}
			pterm.Success.Printf("Results written to %s\n", outputFile)
		}

		pterm.Println()
		pterm.DefaultSection.Println("Phase 3: Final Report")
		
		if outputFormat == "table" {
			ui.PrintFindings(filteredFindings)
		} else if outputFormat == "json" {
			jsonData, _ := json.MarshalIndent(filteredFindings, "", "  ")
			fmt.Println(string(jsonData))
		} else if outputFormat == "csv" {
			writeCSVToStdout(filteredFindings)
		}

		pterm.Println()
		pterm.DefaultBox.WithTitle("Summary").Println(
			fmt.Sprintf("Total Findings: %d\nCritical: %d\nHigh: %d\nMedium: %d\nLow: %d",
				len(filteredFindings),
				countByRisk(filteredFindings, models.RiskCritical),
				countByRisk(filteredFindings, models.RiskHigh),
				countByRisk(filteredFindings, models.RiskMedium),
				countByRisk(filteredFindings, models.RiskLow),
			),
		)
	},
}

func scanRegion(region string, deep bool, excludeIDs []string) []models.Finding {
	pterm.Println()
	pterm.DefaultSection.Printf("Phase 1: Initialization (%s)", region)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	spinner := ui.StartSpinner("Connecting to AWS Region: " + region)
	awsClient, err := aws.NewClient(ctx, region)
	if err != nil {
		spinner.Fail("Error initializing AWS client: " + err.Error())
		pterm.Error.Printf("Skipping region %s\n", region)
		return nil
	}
	spinner.Success("Connected to AWS (" + region + ")")

	pterm.Println()
	pterm.DefaultSection.Printf("Phase 2: Discovery & Analysis (%s)", region)

	spinner = ui.StartSpinner("Hunting for Shadow AI artifacts...")
	scn := scanner.New(awsClient, deep)
	findings, err := scn.Scan(ctx, spinner)
	if err != nil {
		spinner.Fail("Scan failed: " + err.Error())
		return nil
	}
	spinner.Success("Scan Complete")

	if len(excludeIDs) > 0 {
		filtered := []models.Finding{}
		for _, f := range findings {
			excluded := false
			for _, id := range excludeIDs {
				if f.InstanceID == id {
					excluded = true
					break
				}
			}
			if !excluded {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	return findings
}

func isValidRegion(region string) bool {
	for _, r := range validRegions {
		if r == region {
			return true
		}
	}
	return false
}

func parseRiskLevel(risk string) models.RiskLevel {
	switch strings.ToUpper(risk) {
	case "CRITICAL":
		return models.RiskCritical
	case "HIGH":
		return models.RiskHigh
	case "MEDIUM":
		return models.RiskMedium
	case "LOW":
		return models.RiskLow
	default:
		return models.RiskLow
	}
}

func filterByRisk(findings []models.Finding, minRisk models.RiskLevel) []models.Finding {
	riskOrder := map[models.RiskLevel]int{
		models.RiskCritical: 4,
		models.RiskHigh:     3,
		models.RiskMedium:   2,
		models.RiskLow:      1,
	}

	minLevel := riskOrder[minRisk]
	filtered := []models.Finding{}

	for _, f := range findings {
		if riskOrder[f.Risk] >= minLevel {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

func countByRisk(findings []models.Finding, risk models.RiskLevel) int {
	count := 0
	for _, f := range findings {
		if f.Risk == risk {
			count++
		}
	}
	return count
}

func writeOutput(findings []models.Finding, format, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	switch format {
	case "json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(findings)
	case "csv":
		return writeCSV(findings, file)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func writeCSV(findings []models.Finding, file *os.File) error {
	writer := csv.NewWriter(file)
	defer writer.Flush()
	err := writer.Write([]string{"Risk", "Service", "InstanceID", "Region", "PublicIP", "Description", "Evidence"})
	if err != nil {
		return err
	}

	for _, f := range findings {
		err := writer.Write([]string{
			string(f.Risk),
			f.Service,
			f.InstanceID,
			f.Region,
			f.PublicIP,
			f.Description,
			f.Evidence,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func writeCSVToStdout(findings []models.Finding) {
	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()

	writer.Write([]string{"Risk", "Service", "InstanceID", "Region", "PublicIP", "Description", "Evidence"})
	for _, f := range findings {
		writer.Write([]string{
			string(f.Risk),
			f.Service,
			f.InstanceID,
			f.Region,
			f.PublicIP,
			f.Description,
			f.Evidence,
		})
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringP("region", "r", "", "AWS Region to scan (e.g. eu-west-1)")
	scanCmd.Flags().Bool("deep", false, "Enable Deep Scan using AWS SSM")
	scanCmd.Flags().String("format", "table", "Output format: table, json, or csv")
	scanCmd.Flags().StringP("output", "o", "", "Write results to file")
	scanCmd.Flags().String("min-risk", "LOW", "Minimum risk level to show (LOW, MEDIUM, HIGH, CRITICAL)")
	scanCmd.Flags().Bool("all-regions", false, "Scan all AWS regions")
	scanCmd.Flags().StringSlice("exclude-ids", []string{}, "Instance IDs to exclude from scan")
	scanCmd.Flags().Bool("s3", false, "Scan S3 buckets for AI models")
}