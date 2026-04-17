package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bikidsx/honey-badger/internal/discovery"
	"github.com/bikidsx/honey-badger/internal/vulnquery"
)

func sampleFindings() []vulnquery.Finding {
	return []vulnquery.Finding{
		{
			ID:          "HB-0001",
			Class:       vulnquery.SQLInjection,
			Severity:    vulnquery.High,
			Title:       "Potential SQL injection",
			Description: "Call to database execution function.",
			File:        "db/handler.py",
			StartRow:    41,
			StartCol:    8,
			EndRow:      41,
			EndCol:      30,
			Language:    discovery.Python,
		},
		{
			ID:          "HB-0002",
			Class:       vulnquery.CommandInjection,
			Severity:    vulnquery.Critical,
			Title:       "Potential command injection",
			Description: "Call to OS command execution function.",
			File:        "utils/exec.py",
			StartRow:    15,
			StartCol:    4,
			EndRow:      15,
			EndCol:      20,
			Language:    discovery.Python,
		},
		{
			ID:          "HB-0003",
			Class:       vulnquery.HardcodedSecret,
			Severity:    vulnquery.High,
			Title:       "Hardcoded password",
			Description: "Hardcoded secret detected in string literal.",
			File:        "config.py",
			StartRow:    3,
			StartCol:    0,
			EndRow:      3,
			EndCol:      25,
			Language:    discovery.Python,
		},
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSARIF(&buf, sampleFindings(), "dev")
	if err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	// Validate it's valid JSON
	var report SARIFReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	// Check schema
	if report.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", report.Version)
	}
	if report.Schema == "" {
		t.Error("expected SARIF schema URI")
	}

	// Check runs
	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]

	// Check tool
	if run.Tool.Driver.Name != "Honey Badger" {
		t.Errorf("expected tool name 'Honey Badger', got %s", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "dev" {
		t.Errorf("expected version 'dev', got %s", run.Tool.Driver.Version)
	}

	// Check results
	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(run.Results))
	}

	// Check rules are deduplicated
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(run.Tool.Driver.Rules))
	}
}

func TestSARIFResultFields(t *testing.T) {
	var buf bytes.Buffer
	WriteSARIF(&buf, sampleFindings(), "dev")

	var report SARIFReport
	json.Unmarshal(buf.Bytes(), &report)

	result := report.Runs[0].Results[0]

	if result.RuleID != "sql-injection" {
		t.Errorf("expected ruleId 'sql-injection', got %s", result.RuleID)
	}
	if result.Level != "error" {
		t.Errorf("expected level 'error' for high severity, got %s", result.Level)
	}
	if len(result.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(result.Locations))
	}

	loc := result.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "db/handler.py" {
		t.Errorf("expected URI 'db/handler.py', got %s", loc.ArtifactLocation.URI)
	}
	// SARIF uses 1-based lines
	if loc.Region.StartLine != 42 {
		t.Errorf("expected StartLine 42 (1-based), got %d", loc.Region.StartLine)
	}
}

func TestSARIFSeverityMapping(t *testing.T) {
	tests := []struct {
		severity vulnquery.Severity
		want     string
	}{
		{vulnquery.Critical, "error"},
		{vulnquery.High, "error"},
		{vulnquery.Medium, "warning"},
		{vulnquery.Low, "note"},
		{vulnquery.Info, "note"},
	}

	for _, tt := range tests {
		got := severityToSARIF(tt.severity)
		if got != tt.want {
			t.Errorf("severityToSARIF(%s) = %s, want %s", tt.severity, got, tt.want)
		}
	}
}

func TestSARIFEmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSARIF(&buf, nil, "dev")
	if err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	var report SARIFReport
	json.Unmarshal(buf.Bytes(), &report)

	if len(report.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(report.Runs[0].Results))
	}
}

func TestSARIFRuleDeduplication(t *testing.T) {
	findings := []vulnquery.Finding{
		{Class: vulnquery.SQLInjection, Severity: vulnquery.High, Title: "SQLi 1"},
		{Class: vulnquery.SQLInjection, Severity: vulnquery.High, Title: "SQLi 2"},
		{Class: vulnquery.CommandInjection, Severity: vulnquery.Critical, Title: "CMDi"},
	}

	var buf bytes.Buffer
	WriteSARIF(&buf, findings, "dev")

	var report SARIFReport
	json.Unmarshal(buf.Bytes(), &report)

	// Two unique classes -> two rules
	if len(report.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 deduplicated rules, got %d", len(report.Runs[0].Tool.Driver.Rules))
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, sampleFindings())
	if err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	// Validate it's valid JSON
	var findings []vulnquery.Finding
	if err := json.Unmarshal(buf.Bytes(), &findings); err != nil {
		t.Fatalf("JSON output is not valid: %v", err)
	}
	if len(findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(findings))
	}
}

func TestWriteJSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	WriteJSON(&buf, nil)

	output := strings.TrimSpace(buf.String())
	if output != "null" {
		t.Errorf("expected null for empty findings, got %s", output)
	}
}

func TestWriteMarkdown(t *testing.T) {
	var buf bytes.Buffer
	err := WriteMarkdown(&buf, sampleFindings())
	if err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "# 🦡 Honey Badger Security Report") {
		t.Error("expected report header")
	}
	if !strings.Contains(output, "## Summary") {
		t.Error("expected summary section")
	}
	if !strings.Contains(output, "## Findings") {
		t.Error("expected findings section")
	}
	if !strings.Contains(output, "HB-0001") {
		t.Error("expected finding ID HB-0001")
	}
	if !strings.Contains(output, "db/handler.py:42:9") {
		t.Error("expected file location with 1-based line numbers")
	}
	if !strings.Contains(output, "critical") {
		t.Error("expected critical severity in summary")
	}
}

func TestWriteMarkdownEmpty(t *testing.T) {
	var buf bytes.Buffer
	WriteMarkdown(&buf, nil)

	output := buf.String()
	if !strings.Contains(output, "No vulnerabilities found") {
		t.Error("expected 'no vulnerabilities' message for empty findings")
	}
}

func TestWriteMarkdownSeveritySummary(t *testing.T) {
	var buf bytes.Buffer
	WriteMarkdown(&buf, sampleFindings())

	output := buf.String()
	// Should have critical: 1, high: 2
	if !strings.Contains(output, "| critical | 1 |") {
		t.Error("expected critical count of 1")
	}
	if !strings.Contains(output, "| high | 2 |") {
		t.Error("expected high count of 2")
	}
}
