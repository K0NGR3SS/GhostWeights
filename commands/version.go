package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of GhostWeights",
	Long:  `All software has versions. This is GhostWeights's.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("GhostWeights v1.0")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}