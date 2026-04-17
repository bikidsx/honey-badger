// Package report generates output from vulnerability findings in SARIF, JSON,
// and Markdown formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/bikidas/honey-badger/internal/vulnquery"
)

// --- SARIF types (v2.1.0) ---

// SARIFReport is the top-level SARIF document.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool driver.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule describes a vulnerability detection rule.
type SARIFRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription SARIFMessage    `json:"shortDescription"`
	DefaultConfig    SARIFRuleConfig `json:"defaultConfiguration"`
}

// SARIFRuleConfig holds rule severity.
type SARIFRuleConfig struct {
	Level string `json:"level"`
}

// SARIFResult is a single finding.
type SARIFResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   SARIFMessage     `json:"message"`
	Locations []SARIFLocation  `json:"locations"`
}

// SARIFMessage holds a text message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation describes where a finding occurs.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation points to a file and region.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

// SARIFArtifactLocation identifies a file.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion identifies a line/column range.
type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

// severityToSARIF maps our severity to SARIF levels.
func severityToSARIF(s vulnquery.Severity) string {
	switch s {
	case vulnquery.Critical, vulnquery.High:
		return "error"
	case vulnquery.Medium:
		return "warning"
	case vulnquery.Low, vulnquery.Info:
		return "note"
	default:
		return "note"
	}
}

// WriteSARIF writes findings as a SARIF v2.1.0 JSON document.
func WriteSARIF(w io.Writer, findings []vulnquery.Finding, version string) error {
	rules := buildRules(findings)
	results := make([]SARIFResult, 0, len(findings))

	for _, f := range findings {
		results = append(results, SARIFResult{
			RuleID:  string(f.Class),
			Level:   severityToSARIF(f.Severity),
			Message: SARIFMessage{Text: f.Title + ": " + f.Description},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: f.File},
					Region: SARIFRegion{
						StartLine:   f.StartRow + 1, // SARIF uses 1-based lines
						StartColumn: f.StartCol + 1,
						EndLine:     f.EndRow + 1,
						EndColumn:   f.EndCol + 1,
					},
				},
			}},
		})
	}

	report := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:           "Honey Badger",
					Version:        version,
					InformationURI: "https://github.com/bikidas/honey-badger",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// buildRules deduplicates finding classes into SARIF rules.
func buildRules(findings []vulnquery.Finding) []SARIFRule {
	seen := make(map[vulnquery.VulnClass]bool)
	var rules []SARIFRule
	for _, f := range findings {
		if seen[f.Class] {
			continue
		}
		seen[f.Class] = true
		rules = append(rules, SARIFRule{
			ID:               string(f.Class),
			Name:             string(f.Class),
			ShortDescription: SARIFMessage{Text: f.Title},
			DefaultConfig:    SARIFRuleConfig{Level: severityToSARIF(f.Severity)},
		})
	}
	return rules
}

// WriteJSON writes findings as a JSON array.
func WriteJSON(w io.Writer, findings []vulnquery.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// WriteMarkdown writes findings as a Markdown report.
func WriteMarkdown(w io.Writer, findings []vulnquery.Finding) error {
	var b strings.Builder

	b.WriteString("# 🦡 Honey Badger Security Report\n\n")

	if len(findings) == 0 {
		b.WriteString("No vulnerabilities found. Honey Badger is satisfied.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}

	// Summary
	counts := make(map[vulnquery.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("| Severity | Count |\n|---|---|\n"))
	for _, sev := range []vulnquery.Severity{vulnquery.Critical, vulnquery.High, vulnquery.Medium, vulnquery.Low, vulnquery.Info} {
		if c := counts[sev]; c > 0 {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", sev, c))
		}
	}
	b.WriteString("\n")

	// Findings
	b.WriteString("## Findings\n\n")
	for _, f := range findings {
		b.WriteString(fmt.Sprintf("### %s [%s] %s\n\n", f.ID, f.Severity, f.Title))
		b.WriteString(fmt.Sprintf("- **File:** `%s:%d:%d`\n", f.File, f.StartRow+1, f.StartCol+1))
		b.WriteString(fmt.Sprintf("- **Class:** %s\n", f.Class))
		b.WriteString(fmt.Sprintf("- **Language:** %s\n", f.Language))
		b.WriteString(fmt.Sprintf("- **Description:** %s\n\n", f.Description))
	}

	_, err := io.WriteString(w, b.String())
	return err
}
