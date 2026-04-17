package integration_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bikidsx/honey-badger/internal/cpg"
	"github.com/bikidsx/honey-badger/internal/discovery"
	"github.com/bikidsx/honey-badger/internal/parser"
	"github.com/bikidsx/honey-badger/internal/report"
	"github.com/bikidsx/honey-badger/internal/vulnquery"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	// Find testdata relative to project root
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// We're in test/, go up one level
	dir := filepath.Join(wd, "..", "testdata", "vulnerable-app")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("testdata not found at %s: %v", dir, err)
	}
	return dir
}

// TestFullPipeline runs the complete scan pipeline end-to-end.
func TestFullPipeline(t *testing.T) {
	dir := testdataDir(t)

	// Step 1: Discovery
	disc, err := discovery.Scan(dir, nil)
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}
	if len(disc.Files) < 3 {
		t.Fatalf("expected at least 3 files, got %d", len(disc.Files))
	}

	// Should detect both Python and Go
	if disc.Stats[discovery.Python] < 2 {
		t.Errorf("expected at least 2 Python files, got %d", disc.Stats[discovery.Python])
	}
	if disc.Stats[discovery.Go] < 1 {
		t.Errorf("expected at least 1 Go file, got %d", disc.Stats[discovery.Go])
	}

	// Step 2: Parse all files
	var results []*parser.ParseResult
	for _, f := range disc.Files {
		absPath := f.Path
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(dir, f.Path)
		}
		pr, err := parser.ParseFile(absPath, f.Language)
		if err != nil {
			t.Logf("skipping %s: %v", f.Path, err)
			continue
		}
		results = append(results, pr)
	}
	if len(results) < 3 {
		t.Fatalf("expected at least 3 parsed files, got %d", len(results))
	}

	// Step 3: Build CPG
	graph := cpg.Build(results)
	stats := graph.Stats()

	if stats["functions"] == 0 {
		t.Error("expected functions in CPG")
	}
	if stats["calls"] == 0 {
		t.Error("expected calls in CPG")
	}

	// Step 4: Run vulnerability queries
	engine := vulnquery.NewEngine(graph)
	findings := engine.Run()

	if len(findings) == 0 {
		t.Fatal("expected vulnerabilities in the test app")
	}

	// Verify we find the expected vulnerability classes
	classes := make(map[vulnquery.VulnClass]bool)
	for _, f := range findings {
		classes[f.Class] = true
	}

	expectedClasses := []vulnquery.VulnClass{
		vulnquery.SQLInjection,
		vulnquery.CommandInjection,
		vulnquery.HardcodedSecret,
	}
	for _, ec := range expectedClasses {
		if !classes[ec] {
			t.Errorf("expected to find %s vulnerability", ec)
		}
	}

	t.Logf("Found %d vulnerabilities across %d classes", len(findings), len(classes))
	for _, f := range findings {
		t.Logf("  [%s] %s in %s:%d", f.Severity, f.Title, f.File, f.StartRow+1)
	}
}

// TestSARIFOutput verifies the full pipeline produces valid SARIF.
func TestSARIFOutput(t *testing.T) {
	dir := testdataDir(t)

	disc, err := discovery.Scan(dir, nil)
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}

	var results []*parser.ParseResult
	for _, f := range disc.Files {
		absPath := f.Path
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(dir, f.Path)
		}
		pr, err := parser.ParseFile(absPath, f.Language)
		if err != nil {
			continue
		}
		results = append(results, pr)
	}

	graph := cpg.Build(results)
	engine := vulnquery.NewEngine(graph)
	findings := engine.Run()

	var buf strings.Builder
	err = report.WriteSARIF(&buf, findings, "test")
	if err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"version": "2.1.0"`) {
		t.Error("SARIF output missing version")
	}
	if !strings.Contains(output, `"Honey Badger"`) {
		t.Error("SARIF output missing tool name")
	}
	if !strings.Contains(output, `"ruleId"`) {
		t.Error("SARIF output missing results")
	}
}

// TestLanguageFiltering verifies --langs filtering works end-to-end.
func TestLanguageFiltering(t *testing.T) {
	dir := testdataDir(t)

	// Only scan Python
	disc, err := discovery.Scan(dir, &discovery.Options{
		FilterLangs: []discovery.Language{discovery.Python},
	})
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}

	for _, f := range disc.Files {
		if f.Language != discovery.Python {
			t.Errorf("expected only Python files, got %s for %s", f.Language, f.Path)
		}
	}
}

// TestFocusedScan verifies --focus filtering works end-to-end.
func TestFocusedScan(t *testing.T) {
	dir := testdataDir(t)

	disc, _ := discovery.Scan(dir, nil)
	var results []*parser.ParseResult
	for _, f := range disc.Files {
		absPath := f.Path
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(dir, f.Path)
		}
		pr, err := parser.ParseFile(absPath, f.Language)
		if err != nil {
			continue
		}
		results = append(results, pr)
	}

	graph := cpg.Build(results)
	engine := vulnquery.NewEngine(graph)

	// Only check for secrets
	findings := engine.RunFocused(vulnquery.HardcodedSecret)
	for _, f := range findings {
		if f.Class != vulnquery.HardcodedSecret {
			t.Errorf("focused scan returned non-secret finding: %s", f.Class)
		}
	}
	if len(findings) == 0 {
		t.Error("expected at least one hardcoded secret")
	}
}

// TestSeverityFiltering verifies CI mode severity filtering.
func TestSeverityFiltering(t *testing.T) {
	dir := testdataDir(t)

	disc, _ := discovery.Scan(dir, nil)
	var results []*parser.ParseResult
	for _, f := range disc.Files {
		absPath := f.Path
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(dir, f.Path)
		}
		pr, err := parser.ParseFile(absPath, f.Language)
		if err != nil {
			continue
		}
		results = append(results, pr)
	}

	graph := cpg.Build(results)
	engine := vulnquery.NewEngine(graph)
	findings := engine.Run()

	critical := vulnquery.FilterBySeverity(findings, vulnquery.Critical)
	high := vulnquery.FilterBySeverity(findings, vulnquery.High)

	if len(critical) == 0 {
		t.Error("expected critical findings in vulnerable app")
	}
	if len(high) <= len(critical) {
		t.Error("expected more high+ findings than critical-only")
	}
}
