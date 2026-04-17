package cmd

import (
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of Honey Badger",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Printf("hb version %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
