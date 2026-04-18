// Package integrations provides runners for external security tools
// (Trivy, Semgrep) and normalizes their output into Honey Badger findings.
// Tools are optional — if not installed, the runner returns an empty result.
package integrations

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/bikidsx/honey-badger/internal/vulnquery"
)

// ExternalFinding is a normalized finding from an external tool.
type ExternalFinding struct {
	vulnquery.Finding
	Source string // "trivy" or "semgrep"
}

// ToolAvailable checks if a CLI tool is on PATH.
func ToolAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// --- Trivy ---

// trivyResult is the minimal JSON structure we need from `trivy fs --format json`.
type trivyResult struct {
	Results []trivyTarget `json:"Results"`
}

type trivyTarget struct {
	Target          string            `json:"Target"`
	Vulnerabilities []trivyVuln       `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	Severity        string `json:"Severity"`
	Title           string `json:"Title"`
	Description     string `json:"Description"`
}

// RunTrivy runs `trivy fs` on the target directory and returns normalized findings.
// Returns nil, nil if trivy is not installed.
func RunTrivy(target string) ([]ExternalFinding, error) {
	if !ToolAvailable("trivy") {
		return nil, nil
	}

	out, err := exec.Command("trivy", "fs", "--format", "json", "--scanners", "vuln", "-q", target).Output()
	if err != nil {
		// trivy may exit non-zero when vulns found — check if we got output
		if len(out) == 0 {
			return nil, fmt.Errorf("trivy: %w", err)
		}
	}

	var result trivyResult
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("trivy: parse output: %w", err)
	}

	var findings []ExternalFinding
	for _, t := range result.Results {
		for _, v := range t.Vulnerabilities {
			findings = append(findings, ExternalFinding{
				Finding: vulnquery.Finding{
					Class:       vulnquery.VulnClass("sca-" + strings.ToLower(v.Severity)),
					Severity:    mapTrivySeverity(v.Severity),
					Title:       fmt.Sprintf("[Trivy] %s in %s@%s", v.VulnerabilityID, v.PkgName, v.InstalledVersion),
					Description: v.Title,
					File:        t.Target,
				},
				Source: "trivy",
			})
		}
	}
	return findings, nil
}

func mapTrivySeverity(s string) vulnquery.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return vulnquery.Critical
	case "HIGH":
		return vulnquery.High
	case "MEDIUM":
		return vulnquery.Medium
	case "LOW":
		return vulnquery.Low
	default:
		return vulnquery.Info
	}
}


// --- Semgrep ---

// semgrepOutput is the minimal JSON structure from `semgrep --json`.
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string            `json:"message"`
	Severity string            `json:"severity"`
	Metadata map[string]interface{} `json:"metadata"`
}

// RunSemgrep runs `semgrep` on the target directory with auto config and returns normalized findings.
// Returns nil, nil if semgrep is not installed.
func RunSemgrep(target string) ([]ExternalFinding, error) {
	if !ToolAvailable("semgrep") {
		return nil, nil
	}

	out, err := exec.Command("semgrep", "--json", "-q", "--config", "auto", target).Output()
	if err != nil {
		if len(out) == 0 {
			return nil, fmt.Errorf("semgrep: %w", err)
		}
	}

	var result semgrepOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("semgrep: parse output: %w", err)
	}

	var findings []ExternalFinding
	for _, r := range result.Results {
		findings = append(findings, ExternalFinding{
			Finding: vulnquery.Finding{
				Class:       mapSemgrepClass(r.CheckID),
				Severity:    mapSemgrepSeverity(r.Extra.Severity),
				Title:       fmt.Sprintf("[Semgrep] %s", r.CheckID),
				Description: r.Extra.Message,
				File:        r.Path,
				StartRow:    r.Start.Line - 1, // normalize to 0-based
				StartCol:    r.Start.Col - 1,
				EndRow:      r.End.Line - 1,
				EndCol:      r.End.Col - 1,
			},
			Source: "semgrep",
		})
	}
	return findings, nil
}

func mapSemgrepSeverity(s string) vulnquery.Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return vulnquery.High
	case "WARNING":
		return vulnquery.Medium
	case "INFO":
		return vulnquery.Low
	default:
		return vulnquery.Info
	}
}

func mapSemgrepClass(checkID string) vulnquery.VulnClass {
	lower := strings.ToLower(checkID)
	switch {
	case strings.Contains(lower, "sql"):
		return vulnquery.SQLInjection
	case strings.Contains(lower, "command") || strings.Contains(lower, "exec") || strings.Contains(lower, "subprocess") || strings.Contains(lower, "shell"):
		return vulnquery.CommandInjection
	case strings.Contains(lower, "ssrf"):
		return vulnquery.SSRF
	case strings.Contains(lower, "xss"):
		return vulnquery.XSS
	case strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "hardcoded"):
		return vulnquery.HardcodedSecret
	case strings.Contains(lower, "path") || strings.Contains(lower, "traversal"):
		return vulnquery.PathTraversal
	case strings.Contains(lower, "deseriali"):
		return vulnquery.Deserialization
	default:
		return vulnquery.VulnClass("semgrep-" + checkID)
	}
}

// RunAll runs all available external tools and returns combined findings.
func RunAll(target string) ([]ExternalFinding, []string) {
	var all []ExternalFinding
	var toolsUsed []string

	if trivyFindings, err := RunTrivy(target); err == nil && len(trivyFindings) > 0 {
		all = append(all, trivyFindings...)
		toolsUsed = append(toolsUsed, "trivy")
	}

	if semgrepFindings, err := RunSemgrep(target); err == nil && len(semgrepFindings) > 0 {
		all = append(all, semgrepFindings...)
		toolsUsed = append(toolsUsed, "semgrep")
	}

	return all, toolsUsed
}
