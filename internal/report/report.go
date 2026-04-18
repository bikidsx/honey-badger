// Package report generates output from vulnerability findings in SARIF, JSON,
// and Markdown formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/bikidsx/honey-badger/internal/vulnquery"
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
					InformationURI: "https://github.com/bikidsx/honey-badger",
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


// WriteHTML writes findings as a minimal monochrome HTML report.
func WriteHTML(w io.Writer, findings []vulnquery.Finding) error {
	counts := make(map[vulnquery.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Honey Badger — Security Report</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: "SF Mono", "Cascadia Code", "Fira Code", Menlo, Consolas, monospace; background: #fff; color: #111; max-width: 860px; margin: 0 auto; padding: 2rem 1.5rem; line-height: 1.6; }
  h1 { font-size: 1.3rem; font-weight: 700; border-bottom: 2px solid #111; padding-bottom: .5rem; margin-bottom: 1.5rem; }
  .meta { font-size: .8rem; color: #666; margin-bottom: 2rem; }
  .summary { display: flex; gap: 1.5rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .stat { border: 1px solid #ddd; padding: .6rem 1rem; min-width: 100px; }
  .stat-num { font-size: 1.4rem; font-weight: 700; }
  .stat-label { font-size: .7rem; text-transform: uppercase; letter-spacing: .05em; color: #666; }
  .finding { border: 1px solid #ddd; padding: 1rem 1.2rem; margin-bottom: .75rem; }
  .finding:hover { border-color: #111; }
  .finding-header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: .4rem; }
  .finding-id { font-weight: 700; font-size: .85rem; }
  .sev { font-size: .7rem; text-transform: uppercase; letter-spacing: .05em; padding: .15rem .5rem; border: 1px solid; }
  .sev-critical { border-color: #111; background: #111; color: #fff; }
  .sev-high { border-color: #111; }
  .sev-medium { border-color: #999; color: #555; }
  .sev-low { border-color: #ccc; color: #999; }
  .sev-info { border-color: #eee; color: #bbb; }
  .finding-title { font-size: .85rem; font-weight: 600; margin-bottom: .3rem; }
  .finding-loc { font-size: .75rem; color: #666; }
  .finding-desc { font-size: .78rem; color: #444; margin-top: .3rem; }
  .tag { font-size: .65rem; background: #f5f5f5; padding: .1rem .4rem; margin-right: .3rem; }
  .empty { text-align: center; padding: 3rem; color: #999; }
  @media (prefers-color-scheme: dark) {
    body { background: #111; color: #eee; }
    .stat, .finding { border-color: #333; }
    .finding:hover { border-color: #eee; }
    .stat-label, .finding-loc { color: #888; }
    .finding-desc { color: #aaa; }
    .tag { background: #222; }
    .sev-critical { background: #eee; color: #111; border-color: #eee; }
    .sev-high { border-color: #eee; }
    .sev-medium { border-color: #666; color: #aaa; }
    .sev-low { border-color: #444; color: #666; }
    h1 { border-bottom-color: #eee; }
    .meta { color: #888; }
  }
</style>
</head>
<body>
<h1>🦡 Honey Badger</h1>
`)

	b.WriteString(fmt.Sprintf(`<p class="meta">%d findings</p>`, len(findings)))

	if len(findings) == 0 {
		b.WriteString(`<p class="empty">No vulnerabilities found. Honey Badger is satisfied.</p>`)
	} else {
		// Summary stats
		b.WriteString(`<div class="summary">`)
		for _, sev := range []vulnquery.Severity{vulnquery.Critical, vulnquery.High, vulnquery.Medium, vulnquery.Low, vulnquery.Info} {
			if c := counts[sev]; c > 0 {
				b.WriteString(fmt.Sprintf(`<div class="stat"><div class="stat-num">%d</div><div class="stat-label">%s</div></div>`, c, sev))
			}
		}
		b.WriteString(`</div>`)

		// Findings
		for _, f := range findings {
			sevClass := "sev-" + string(f.Severity)
			b.WriteString(`<div class="finding">`)
			b.WriteString(fmt.Sprintf(`<div class="finding-header"><span class="finding-id">%s</span><span class="sev %s">%s</span></div>`, f.ID, sevClass, f.Severity))
			b.WriteString(fmt.Sprintf(`<div class="finding-title">%s</div>`, htmlEscape(string(f.Title))))
			b.WriteString(fmt.Sprintf(`<div class="finding-loc">%s:%d:%d`, htmlEscape(f.File), f.StartRow+1, f.StartCol+1))
			if f.Language != "" {
				b.WriteString(fmt.Sprintf(` <span class="tag">%s</span>`, f.Language))
			}
			b.WriteString(fmt.Sprintf(` <span class="tag">%s</span>`, f.Class))
			b.WriteString(`</div>`)
			if f.Description != "" {
				b.WriteString(fmt.Sprintf(`<div class="finding-desc">%s</div>`, htmlEscape(f.Description)))
			}
			b.WriteString(`</div>`)
		}
	}

	b.WriteString(`</body></html>`)
	_, err := io.WriteString(w, b.String())
	return err
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
