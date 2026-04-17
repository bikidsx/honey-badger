package cmd

import (
	"github.com/spf13/cobra"
)

// Version is set at build time via ldflags.
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "hb",
	Short: "Honey Badger — repository-level codebase penetration testing",
	Long:  "Honey Badger don't care about your defenses.\nA semantics-first, language-agnostic security analysis CLI.",
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringP("output", "o", "sarif", "output format: sarif, json, markdown")
}
