package integrations

import (
	"encoding/json"
	"testing"

	"github.com/bikidsx/honey-badger/internal/vulnquery"
)

func TestMapTrivySeverity(t *testing.T) {
	tests := []struct {
		input string
		want  vulnquery.Severity
	}{
		{"CRITICAL", vulnquery.Critical},
		{"HIGH", vulnquery.High},
		{"MEDIUM", vulnquery.Medium},
		{"LOW", vulnquery.Low},
		{"UNKNOWN", vulnquery.Info},
	}
	for _, tt := range tests {
		got := mapTrivySeverity(tt.input)
		if got != tt.want {
			t.Errorf("mapTrivySeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMapSemgrepSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  vulnquery.Severity
	}{
		{"ERROR", vulnquery.High},
		{"WARNING", vulnquery.Medium},
		{"INFO", vulnquery.Low},
		{"", vulnquery.Info},
	}
	for _, tt := range tests {
		got := mapSemgrepSeverity(tt.input)
		if got != tt.want {
			t.Errorf("mapSemgrepSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMapSemgrepClass(t *testing.T) {
	tests := []struct {
		checkID string
		want    vulnquery.VulnClass
	}{
		{"python.lang.security.audit.dangerous-sql-query", vulnquery.SQLInjection},
		{"javascript.express.security.audit.xss.mustache-escape", vulnquery.XSS},
		{"python.lang.security.audit.subprocess-shell-true", vulnquery.CommandInjection},
		{"go.lang.security.audit.net.ssrf", vulnquery.SSRF},
		{"generic.secrets.hardcoded-password", vulnquery.HardcodedSecret},
		{"php.lang.security.deserialization", vulnquery.Deserialization},
		{"java.lang.security.audit.path-traversal", vulnquery.PathTraversal},
		{"some.unknown.rule", vulnquery.VulnClass("semgrep-some.unknown.rule")},
	}
	for _, tt := range tests {
		got := mapSemgrepClass(tt.checkID)
		if got != tt.want {
			t.Errorf("mapSemgrepClass(%q) = %q, want %q", tt.checkID, got, tt.want)
		}
	}
}

func TestParseTrivyJSON(t *testing.T) {
	raw := `{
		"Results": [{
			"Target": "package-lock.json",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2024-1234",
				"PkgName": "lodash",
				"InstalledVersion": "4.17.20",
				"Severity": "HIGH",
				"Title": "Prototype Pollution",
				"Description": "lodash before 4.17.21 is vulnerable"
			}]
		}]
	}`
	var result trivyResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("failed to parse trivy JSON: %v", err)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	if len(result.Results[0].Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(result.Results[0].Vulnerabilities))
	}
	v := result.Results[0].Vulnerabilities[0]
	if v.VulnerabilityID != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", v.VulnerabilityID)
	}
}

func TestParseSemgrepJSON(t *testing.T) {
	raw := `{
		"results": [{
			"check_id": "python.lang.security.audit.dangerous-sql-query",
			"path": "app.py",
			"start": {"line": 10, "col": 5},
			"end": {"line": 10, "col": 40},
			"extra": {
				"message": "Detected SQL query built with string concatenation",
				"severity": "ERROR",
				"metadata": {}
			}
		}]
	}`
	var result semgrepOutput
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("failed to parse semgrep JSON: %v", err)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	r := result.Results[0]
	if r.Start.Line != 10 {
		t.Errorf("expected line 10, got %d", r.Start.Line)
	}
	if r.Extra.Severity != "ERROR" {
		t.Errorf("expected ERROR severity, got %s", r.Extra.Severity)
	}
}

func TestRunAllNoTools(t *testing.T) {
	// RunAll should gracefully return empty when tools aren't installed
	// (or are installed — either way it shouldn't crash)
	findings, _ := RunAll(".")
	// We can't assert exact counts since tools may or may not be installed,
	// but it should not panic
	_ = findings
}
