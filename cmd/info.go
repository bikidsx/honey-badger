package cmd

import (
	"fmt"

	"github.com/bikidas/honey-badger/internal/discovery"
	"github.com/spf13/cobra"
)

var infoCmd = &cobra.Command{
	Use:   "info [path]",
	Short: "Show detected languages and file counts",
	Long:  "List all detected languages, file counts, and basic repository metadata.",
	Args:  cobra.ExactArgs(1),
	RunE:  runInfo,
}

func init() {
	rootCmd.AddCommand(infoCmd)
}

func runInfo(cmd *cobra.Command, args []string) error {
	target := args[0]

	disc, err := discovery.Scan(target, nil)
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}

	cmd.Printf("🦡 Honey Badger info: %s\n\n", target)
	cmd.Printf("Total files: %d\n\n", len(disc.Files))

	if len(disc.Stats) == 0 {
		cmd.Printf("No recognized source files found.\n")
		return nil
	}

	cmd.Printf("Languages:\n")
	for lang, count := range disc.Stats {
		cmd.Printf("  %-15s %d files\n", lang, count)
	}

	return nil
}
