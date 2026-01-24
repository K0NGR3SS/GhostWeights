// commands/scan.go
package commands

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/K0NGR3SS/ghostweights/internal/aws"
	"github.com/K0NGR3SS/ghostweights/internal/scanner"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Start the Shadow AI hunt",
	Long:  `Scans the target AWS region for EC2 instances exposing AI/ML ports (Ollama, Ray, Streamlit) and other suspicious artifacts.`,
	Run: func(cmd *cobra.Command, args []string) {
		region, _ := cmd.Flags().GetString("region")
		
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		fmt.Printf("[*] Initializing AWS Client for region: %s\n", region)
		awsClient, err := aws.NewClient(ctx, region)
		if err != nil {
			fmt.Printf("Error initializing AWS client: %v\n", err)
			os.Exit(1)
		}

		scn := scanner.New(awsClient)
		findings, err := scn.Scan(ctx)
		if err != nil {
			fmt.Printf("Scan failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Scan complete. Found %d potential issues.\n", len(findings))
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
