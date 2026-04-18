package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/bikidsx/honey-badger/internal/cpg"
	"github.com/bikidsx/honey-badger/internal/discovery"
	"github.com/bikidsx/honey-badger/internal/parser"
	"github.com/spf13/cobra"
)

var understandCmd = &cobra.Command{
	Use:   "understand [path]",
	Short: "Map a codebase without attacking it",
	Long:  "Build a semantic understanding of the codebase: languages, call graph, entry points, trust boundaries.",
	Args:  cobra.ExactArgs(1),
	RunE:  runUnderstand,
}

func init() {
	understandCmd.Flags().String("show", "", "what to display: callgraph, entrypoints, stats")
	rootCmd.AddCommand(understandCmd)
}

func runUnderstand(cmd *cobra.Command, args []string) error {
	target := args[0]
	show, _ := cmd.Flags().GetString("show")

	cmd.Printf("🦡 Honey Badger understanding: %s\n", target)

	// Discover
	disc, err := discovery.Scan(target, nil)
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}

	// Parse
	var results []*parser.ParseResult
	for _, f := range disc.Files {
		pr, err := parser.ParseFile(filepath.Join(disc.Root, f.Path), f.Language)
		if err != nil {
			continue
		}
		results = append(results, pr)
	}

	// Build CPG
	graph := cpg.Build(results)
	stats := graph.Stats()

	// Display based on --show flag
	switch show {
	case "callgraph":
		cmd.Printf("\n📊 Call Graph:\n")
		for _, e := range graph.Edges {
			if e.Kind == cpg.EdgeCalls {
				from := graph.Nodes[e.From]
				to := graph.Nodes[e.To]
				if from != nil && to != nil {
					cmd.Printf("  %s (%s:%d) → %s (%s:%d)\n",
						from.Name, from.File, from.StartRow+1,
						to.Name, to.File, to.StartRow+1)
				}
			}
		}
	case "entrypoints":
		cmd.Printf("\n🚪 Entry Points (functions with no callers):\n")
		funcs := graph.NodesOfKind(cpg.KindFunction)
		for _, fn := range funcs {
			callers := graph.CallersOf(fn.ID)
			if len(callers) == 0 {
				cmd.Printf("  %s (%s:%d)\n", fn.Name, fn.File, fn.StartRow+1)
			}
		}
	default:
		cmd.Printf("\n📈 Codebase Statistics:\n")
		cmd.Printf("  Files:          %d\n", stats["files"])
		cmd.Printf("  Functions:      %d\n", stats["functions"])
		cmd.Printf("  Calls:          %d\n", stats["calls"])
		cmd.Printf("  Imports:        %d\n", stats["imports"])
		cmd.Printf("  Strings:        %d\n", stats["strings"])
		cmd.Printf("  Resolved calls: %d\n", stats["resolved_calls"])

		cmd.Printf("\n📁 Languages:\n")
		for lang, count := range disc.Stats {
			cmd.Printf("  %-15s %d files\n", lang, count)
		}
	}

	return nil
}
