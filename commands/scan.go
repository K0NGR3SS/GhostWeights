package commands

import (
	"context"
	"os"
	"time"

	"github.com/K0NGR3SS/ghostweights/internal/aws"
	"github.com/K0NGR3SS/ghostweights/internal/scanner"
	"github.com/K0NGR3SS/ghostweights/internal/ui"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Start the Shadow AI hunt",
	Long:  `Scans the target AWS region for EC2 instances exposing AI/ML ports (Ollama, Ray, Streamlit).`,
	Run: func(cmd *cobra.Command, args []string) {
		region, _ := cmd.Flags().GetString("region")
		deep, _ := cmd.Flags().GetBool("deep")

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

		pterm.Println()
		pterm.DefaultSection.Println("Phase 1: Initialization")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		spinner := ui.StartSpinner("Connecting to AWS Region: " + region)
		awsClient, err := aws.NewClient(ctx, region)
		if err != nil {
			spinner.Fail("Error initializing AWS client: " + err.Error())
			os.Exit(1)
		}
		spinner.Success("Connected to AWS (" + region + ")")

		pterm.Println()
		pterm.DefaultSection.Println("Phase 2: Discovery & Analysis")

		spinner = ui.StartSpinner("Hunting for Shadow AI artifacts...")
		scn := scanner.New(awsClient, deep)
		findings, err := scn.Scan(ctx, spinner)
		if err != nil {
			spinner.Fail("Scan failed: " + err.Error())
			os.Exit(1)
		}
		spinner.Success("Scan Complete")

		pterm.Println()
		pterm.DefaultSection.Println("Phase 3: Final Report")
		ui.PrintFindings(findings)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringP("region", "r", "", "AWS Region to scan (e.g. eu-west-1)")
	scanCmd.Flags().Bool("deep", false, "Enable Deep Scan using AWS SSM")
}
