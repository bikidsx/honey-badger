package cmd

import (
	"fmt"
	"os"

	"github.com/bikidas/honey-badger/internal/cpg"
	"github.com/bikidas/honey-badger/internal/discovery"
	"github.com/bikidas/honey-badger/internal/parser"
	"github.com/bikidas/honey-badger/internal/report"
	"github.com/bikidas/honey-badger/internal/vulnquery"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a codebase for vulnerabilities",
	Long:  "Ingest, build CPG, and run vulnerability analysis on the target codebase.",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringSlice("focus", nil, "focus on specific vuln classes: sql-injection,command-injection,ssrf,xss,hardcoded-secret,path-traversal")
	scanCmd.Flags().StringSlice("langs", nil, "scan only specific languages: python,go,javascript,typescript")
	scanCmd.Flags().Bool("ci", false, "CI/CD mode — exit 1 if critical vulns found")
	scanCmd.Flags().String("fail-on", "critical", "severity threshold for CI failure: critical, high, medium, low")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]
	outputFmt, _ := cmd.Flags().GetString("output")
	focus, _ := cmd.Flags().GetStringSlice("focus")
	langs, _ := cmd.Flags().GetStringSlice("langs")
	ciMode, _ := cmd.Flags().GetBool("ci")
	failOn, _ := cmd.Flags().GetString("fail-on")

	cmd.Printf("🦡 Honey Badger scanning: %s\n", target)

	// Step 1: Discover files
	var opts *discovery.Options
	if len(langs) > 0 {
		filterLangs := make([]discovery.Language, 0, len(langs))
		for _, l := range langs {
			filterLangs = append(filterLangs, discovery.Language(l))
		}
		opts = &discovery.Options{FilterLangs: filterLangs}
	}

	disc, err := discovery.Scan(target, opts)
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	cmd.Printf("   Found %d files across %d languages\n", len(disc.Files), len(disc.Stats))

	// Step 2: Parse files
	var results []*parser.ParseResult
	for _, f := range disc.Files {
		pr, err := parser.ParseFile(f.Path, f.Language)
		if err != nil {
			continue // skip unparseable files
		}
		results = append(results, pr)
	}
	cmd.Printf("   Parsed %d files\n", len(results))

	// Step 3: Build CPG
	graph := cpg.Build(results)
	stats := graph.Stats()
	cmd.Printf("   CPG: %d nodes, %d edges, %d resolved calls\n",
		stats["nodes"], stats["edges"], stats["resolved_calls"])

	// Step 4: Run vulnerability queries
	engine := vulnquery.NewEngine(graph)
	var findings []vulnquery.Finding
	if len(focus) > 0 {
		classes := make([]vulnquery.VulnClass, 0, len(focus))
		for _, f := range focus {
			classes = append(classes, vulnquery.VulnClass(f))
		}
		findings = engine.RunFocused(classes...)
	} else {
		findings = engine.Run()
	}
	cmd.Printf("   Found %d potential vulnerabilities\n", len(findings))

	// Step 5: Output report
	w := cmd.OutOrStdout()
	switch outputFmt {
	case "sarif":
		if err := report.WriteSARIF(w, findings, Version); err != nil {
			return fmt.Errorf("write SARIF: %w", err)
		}
	case "json":
		if err := report.WriteJSON(w, findings); err != nil {
			return fmt.Errorf("write JSON: %w", err)
		}
	case "markdown":
		if err := report.WriteMarkdown(w, findings); err != nil {
			return fmt.Errorf("write markdown: %w", err)
		}
	default:
		return fmt.Errorf("unknown output format: %s", outputFmt)
	}

	// CI mode: exit with error if findings exceed threshold
	if ciMode {
		sev := vulnquery.Severity(failOn)
		critical := vulnquery.FilterBySeverity(findings, sev)
		if len(critical) > 0 {
			cmd.PrintErrf("CI failure: %d findings at or above %s severity\n", len(critical), failOn)
			os.Exit(1)
		}
	}

	return nil
}
