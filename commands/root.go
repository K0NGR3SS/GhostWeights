package commands

import (
	"os"

	"github.com/K0NGR3SS/ghostweights/internal/ui"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ghostweights",
	Short: "GhostWeights hunts for Shadow AI workloads in AWS",
	Long:  `GhostWeights is a security tool to discover unauthorized AI/ML artifacts (Ollama, Ray, Streamlit) running in your AWS environment.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func Execute() {
	ui.PrintBanner()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("region", "r", "us-east-1", "AWS Region to scan")
}
