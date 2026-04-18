package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bikidsx/honey-badger/internal/cpg"
	"github.com/bikidsx/honey-badger/internal/discovery"
	"github.com/bikidsx/honey-badger/internal/integrations"
	"github.com/bikidsx/honey-badger/internal/parser"
	"github.com/bikidsx/honey-badger/internal/report"
	"github.com/bikidsx/honey-badger/internal/vulnquery"
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
	scanCmd.Flags().StringSlice("exclude", nil, "directories or file patterns to exclude from scan")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]
	outputFmt, _ := cmd.Flags().GetString("output")
	focus, _ := cmd.Flags().GetStringSlice("focus")
	langs, _ := cmd.Flags().GetStringSlice("langs")
	ciMode, _ := cmd.Flags().GetBool("ci")
	failOn, _ := cmd.Flags().GetString("fail-on")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")

	cmd.Printf("🦡 Honey Badger scanning: %s\n", target)

	// Step 1: Discover files
	var opts *discovery.Options
	if len(langs) > 0 || len(exclude) > 0 {
		opts = &discovery.Options{}
		if len(langs) > 0 {
			filterLangs := make([]discovery.Language, 0, len(langs))
			for _, l := range langs {
				filterLangs = append(filterLangs, discovery.Language(l))
			}
			opts.FilterLangs = filterLangs
		}
		if len(exclude) > 0 {
			ignoreDirs := make(map[string]bool, len(exclude))
			for _, e := range exclude {
				ignoreDirs[e] = true
			}
			opts.IgnoreDirs = ignoreDirs
		}
	}

	disc, err := discovery.Scan(target, opts)
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	cmd.Printf("   Found %d files across %d languages\n", len(disc.Files), len(disc.Stats))

	// Step 2: Parse files (parallel worker pool)
	type parseJob struct {
		path string
		lang discovery.Language
	}
	workers := runtime.GOMAXPROCS(0)
	if workers > len(disc.Files) {
		workers = len(disc.Files)
	}
	if workers < 1 {
		workers = 1
	}

	total := len(disc.Files)
	var parsed int64
	jobs := make(chan parseJob, total)
	resultsCh := make(chan *parser.ParseResult, total)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				pr, err := parser.ParseFile(j.path, j.lang)
				atomic.AddInt64(&parsed, 1)
				if err != nil {
					continue
				}
				resultsCh <- pr
			}
		}()
	}

	for _, f := range disc.Files {
		jobs <- parseJob{path: filepath.Join(disc.Root, f.Path), lang: f.Language}
	}
	close(jobs)

	// Animated progress bar
	done := make(chan struct{})
	go func() {
		spinner := []string{"▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"}
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		frame := 0
		barWidth := 30
		for {
			select {
			case <-done:
				// Final state
				fmt.Fprintf(cmd.ErrOrStderr(), "\r   Parsing [%s] %d/%d files ✓\n",
					strings.Repeat("█", barWidth), total, total)
				return
			case <-tick.C:
				n := int(atomic.LoadInt64(&parsed))
				pct := float64(n) / float64(total)
				filled := int(pct * float64(barWidth))
				bar := strings.Repeat("█", filled)
				if filled < barWidth {
					bar += spinner[frame%len(spinner)]
					bar += strings.Repeat("░", barWidth-filled-1)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "\r   Parsing [%s] %d/%d files", bar, n, total)
				frame++
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var results []*parser.ParseResult
	for pr := range resultsCh {
		results = append(results, pr)
	}
	close(done)
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

	// Step 5: Run external tools (Trivy, Semgrep) if available
	extFindings, toolsUsed := integrations.RunAll(target)
	if len(toolsUsed) > 0 {
		cmd.Printf("   External tools: %s (%d findings)\n", strings.Join(toolsUsed, ", "), len(extFindings))
		for _, ef := range extFindings {
			findings = append(findings, ef.Finding)
		}
	}

	// Step 6: Output report
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
	case "html":
		htmlPath := filepath.Join(os.TempDir(), "hb-report.html")
		f, err := os.Create(htmlPath)
		if err != nil {
			return fmt.Errorf("create HTML file: %w", err)
		}
		if err := report.WriteHTML(f, findings); err != nil {
			f.Close()
			return fmt.Errorf("write HTML: %w", err)
		}
		f.Close()
		cmd.Printf("   Report: %s\n", htmlPath)
		openBrowser(htmlPath)
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


func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}
