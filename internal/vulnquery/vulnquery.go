// Package vulnquery implements pattern-based vulnerability detection over
// the Code Property Graph. It defines sinks, sources, and detection rules
// for common vulnerability classes: SQL injection, command injection, SSRF,
// XSS, and hardcoded secrets.
package vulnquery

import (
	"regexp"
	"strings"

	"github.com/bikidsx/honey-badger/internal/cpg"
	"github.com/bikidsx/honey-badger/internal/discovery"
)

// Severity levels for findings.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// VulnClass identifies a vulnerability category.
type VulnClass string

const (
	SQLInjection      VulnClass = "sql-injection"
	CommandInjection  VulnClass = "command-injection"
	SSRF              VulnClass = "ssrf"
	XSS               VulnClass = "xss"
	HardcodedSecret   VulnClass = "hardcoded-secret"
	PathTraversal     VulnClass = "path-traversal"
	Deserialization   VulnClass = "insecure-deserialization"
)

// Finding represents a detected vulnerability.
type Finding struct {
	ID          string
	Class       VulnClass
	Severity    Severity
	Title       string
	Description string
	File        string
	StartRow    int
	StartCol    int
	EndRow      int
	EndCol      int
	Language    discovery.Language
	NodeID      cpg.NodeID // CPG node that triggered the finding
}

// sinkDef defines a dangerous function (sink) per language.
type sinkDef struct {
	Language discovery.Language
	Names    []string
	Class    VulnClass
	Severity Severity
	Title    string
	Desc     string
}

// sinkRegistry lists known dangerous sinks per vulnerability class.
var sinkRegistry = []sinkDef{
	// SQL Injection sinks
	{discovery.Python, []string{"execute", "executemany", "raw"}, SQLInjection, High,
		"Potential SQL injection", "Call to database execution function. Verify parameterized queries are used."},
	{discovery.Go, []string{"Exec", "Query", "QueryRow"}, SQLInjection, High,
		"Potential SQL injection", "Call to database query function. Verify parameterized queries are used."},
	{discovery.JavaScript, []string{"query", "execute", "raw"}, SQLInjection, High,
		"Potential SQL injection", "Call to database query function. Verify parameterized queries are used."},

	// Command Injection sinks
	{discovery.Python, []string{"popen", "system", "call", "check_output", "run"}, CommandInjection, Critical,
		"Potential command injection", "Call to OS command execution function."},
	{discovery.Go, []string{"Command", "CommandContext"}, CommandInjection, Critical,
		"Potential command injection", "Call to exec.Command. Verify input is sanitized."},
	{discovery.JavaScript, []string{"exec", "execSync", "spawn", "execFile"}, CommandInjection, Critical,
		"Potential command injection", "Call to child_process execution function."},

	// SSRF sinks
	{discovery.Python, []string{"get", "post", "put", "delete", "request", "urlopen"}, SSRF, High,
		"Potential SSRF", "HTTP request function called. Verify URL is not user-controlled."},
	{discovery.Go, []string{"Get", "Post", "Do", "NewRequest"}, SSRF, High,
		"Potential SSRF", "HTTP request function called. Verify URL is not user-controlled."},
	{discovery.JavaScript, []string{"fetch", "get", "post", "request", "axios"}, SSRF, High,
		"Potential SSRF", "HTTP request function called. Verify URL is not user-controlled."},

	// XSS sinks
	{discovery.JavaScript, []string{"innerHTML", "outerHTML", "write", "writeln"}, XSS, High,
		"Potential XSS", "DOM manipulation with potentially unsanitized input."},
	{discovery.Go, []string{"Fprintf", "Fprintln"}, XSS, Medium,
		"Potential XSS", "Writing to response writer. Verify output is escaped."},

	// Path Traversal sinks
	{discovery.Python, []string{"open"}, PathTraversal, Medium,
		"Potential path traversal", "File open with potentially user-controlled path."},
	{discovery.Go, []string{"Open", "ReadFile", "WriteFile"}, PathTraversal, Medium,
		"Potential path traversal", "File operation with potentially user-controlled path."},

	// Java sinks
	{discovery.Java, []string{"executeQuery", "executeUpdate", "execute", "prepareStatement"}, SQLInjection, High,
		"Potential SQL injection", "Call to JDBC execution function. Verify parameterized queries are used."},
	{discovery.Java, []string{"exec", "getRuntime"}, CommandInjection, Critical,
		"Potential command injection", "Call to Runtime.exec. Verify input is sanitized."},
	{discovery.Java, []string{"openConnection", "openStream"}, SSRF, High,
		"Potential SSRF", "HTTP connection opened. Verify URL is not user-controlled."},
	{discovery.Java, []string{"write", "println"}, XSS, Medium,
		"Potential XSS", "Writing to response. Verify output is escaped."},

	// C# sinks
	{discovery.CSharp, []string{"ExecuteNonQuery", "ExecuteReader", "ExecuteScalar"}, SQLInjection, High,
		"Potential SQL injection", "Call to ADO.NET execution function. Verify parameterized queries are used."},
	{discovery.CSharp, []string{"Start"}, CommandInjection, Critical,
		"Potential command injection", "Call to Process.Start. Verify input is sanitized."},
	{discovery.CSharp, []string{"GetAsync", "PostAsync", "SendAsync", "GetStringAsync"}, SSRF, High,
		"Potential SSRF", "HTTP request function called. Verify URL is not user-controlled."},

	// Rust sinks
	{discovery.Rust, []string{"query", "execute"}, SQLInjection, High,
		"Potential SQL injection", "Call to database execution function. Verify parameterized queries are used."},
	{discovery.Rust, []string{"Command", "spawn", "output"}, CommandInjection, Critical,
		"Potential command injection", "Call to process execution function. Verify input is sanitized."},
	{discovery.Rust, []string{"get", "post", "send"}, SSRF, High,
		"Potential SSRF", "HTTP request function called. Verify URL is not user-controlled."},

	// PHP sinks (vanilla)
	{discovery.PHP, []string{"mysql_query", "mysqli_query", "query", "exec", "prepare"}, SQLInjection, High,
		"Potential SQL injection", "Call to database query function. Verify parameterized queries are used."},
	{discovery.PHP, []string{"exec", "system", "passthru", "shell_exec", "popen", "proc_open"}, CommandInjection, Critical,
		"Potential command injection", "Call to OS command execution function."},
	{discovery.PHP, []string{"file_get_contents", "curl_exec", "fopen"}, SSRF, High,
		"Potential SSRF", "Function may make HTTP requests. Verify URL is not user-controlled."},
	{discovery.PHP, []string{"echo", "print"}, XSS, High,
		"Potential XSS", "Output function called. Verify output is escaped with htmlspecialchars."},
	{discovery.PHP, []string{"include", "require", "include_once", "require_once"}, PathTraversal, Medium,
		"Potential path traversal / file inclusion", "File inclusion with potentially user-controlled path."},

	// PHP deserialization sinks (all languages)
	{discovery.PHP, []string{"unserialize"}, Deserialization, Critical,
		"Insecure deserialization", "unserialize() with untrusted data enables arbitrary object injection."},
	{discovery.Python, []string{"loads", "load"}, Deserialization, High,
		"Potential insecure deserialization", "Pickle/YAML load with potentially untrusted data."},
	{discovery.Java, []string{"readObject", "readUnshared"}, Deserialization, Critical,
		"Insecure deserialization", "Java ObjectInputStream deserialization of untrusted data."},

	// Laravel sinks
	{discovery.PHP, []string{"raw", "selectRaw", "whereRaw", "orderByRaw", "groupByRaw", "havingRaw"}, SQLInjection, High,
		"Laravel raw SQL query", "DB::raw() or raw query method bypasses Eloquent parameterization."},
	{discovery.PHP, []string{"fromSub", "selectSub"}, SQLInjection, Medium,
		"Laravel raw subquery", "Raw subquery may contain unsanitized input."},

	// Symfony sinks
	{discovery.PHP, []string{"executeQuery", "executeStatement"}, SQLInjection, High,
		"Symfony/Doctrine raw query", "Doctrine DBAL direct query execution. Verify parameterized queries."},
}

// secretPatterns detects hardcoded secrets in string literals.
var secretPatterns = []struct {
	Pattern  *regexp.Regexp
	Title    string
	Severity Severity
}{
	{regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}`), "Hardcoded password", High},
	{regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][^'\"]{8,}`), "Hardcoded API key", High},
	{regexp.MustCompile(`(?i)(secret|token)\s*[:=]\s*['\"][^'\"]{8,}`), "Hardcoded secret/token", High},
	{regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['\"][^'\"]+`), "Hardcoded AWS credential", Critical},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS Access Key ID", Critical},
	{regexp.MustCompile(`(?i)-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`), "Private key in source", Critical},
	{regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`), "GitHub personal access token", Critical},
	{regexp.MustCompile(`(?i)(connection_string|conn_str)\s*[:=]\s*['\"][^'\"]{10,}`), "Hardcoded connection string", High},
}

// Engine runs vulnerability queries against a CPG.
type Engine struct {
	graph    *cpg.Graph
	findings []Finding
	counter  int
}

// NewEngine creates a vulnerability query engine for the given graph.
func NewEngine(g *cpg.Graph) *Engine {
	return &Engine{graph: g}
}

// Run executes all vulnerability checks and returns findings.
func (e *Engine) Run() []Finding {
	e.findings = nil
	e.counter = 0

	e.checkSinks()
	e.checkSecrets()
	e.checkSQLStringConcat()

	return e.findings
}

// RunFocused executes only the specified vulnerability classes.
func (e *Engine) RunFocused(classes ...VulnClass) []Finding {
	e.findings = nil
	e.counter = 0

	classSet := make(map[VulnClass]bool, len(classes))
	for _, c := range classes {
		classSet[c] = true
	}

	if classSet[SQLInjection] || classSet[CommandInjection] || classSet[SSRF] || classSet[XSS] || classSet[PathTraversal] || classSet[Deserialization] {
		e.checkSinks(classes...)
	}
	if classSet[HardcodedSecret] {
		e.checkSecrets()
	}
	if classSet[SQLInjection] {
		e.checkSQLStringConcat()
	}

	return e.findings
}

// checkSinks matches call nodes against the sink registry.
func (e *Engine) checkSinks(filterClasses ...VulnClass) {
	filterSet := make(map[VulnClass]bool, len(filterClasses))
	for _, c := range filterClasses {
		filterSet[c] = true
	}

	callNodes := e.graph.NodesOfKind(cpg.KindCall)
	for _, call := range callNodes {
		for _, sink := range sinkRegistry {
			if len(filterSet) > 0 && !filterSet[sink.Class] {
				continue
			}
			if call.Language != sink.Language {
				continue
			}
			for _, name := range sink.Names {
				if call.Name == name {
					e.addFinding(Finding{
						Class:       sink.Class,
						Severity:    sink.Severity,
						Title:       sink.Title,
						Description: sink.Desc,
						File:        call.File,
						StartRow:    call.StartRow,
						StartCol:    call.StartCol,
						EndRow:      call.EndRow,
						EndCol:      call.EndCol,
						Language:    call.Language,
						NodeID:      call.ID,
					})
				}
			}
		}
	}
}

// checkSecrets scans string literals for hardcoded secrets.
func (e *Engine) checkSecrets() {
	stringNodes := e.graph.NodesOfKind(cpg.KindString)
	for _, str := range stringNodes {
		for _, sp := range secretPatterns {
			if sp.Pattern.MatchString(str.Name) {
				e.addFinding(Finding{
					Class:       HardcodedSecret,
					Severity:    sp.Severity,
					Title:       sp.Title,
					Description: "Hardcoded secret detected in string literal.",
					File:        str.File,
					StartRow:    str.StartRow,
					StartCol:    str.StartCol,
					EndRow:      str.EndRow,
					EndCol:      str.EndCol,
					Language:    str.Language,
					NodeID:      str.ID,
				})
				break // one finding per string
			}
		}
	}
}

// checkSQLStringConcat detects SQL queries built via string concatenation.
func (e *Engine) checkSQLStringConcat() {
	stringNodes := e.graph.NodesOfKind(cpg.KindString)
	sqlPattern := regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+`)
	concatIndicators := []string{" + ", "% ", ".format(", "f\"", "f'"}

	for _, str := range stringNodes {
		if !sqlPattern.MatchString(str.Name) {
			continue
		}
		for _, indicator := range concatIndicators {
			if strings.Contains(str.Name, indicator) {
				e.addFinding(Finding{
					Class:       SQLInjection,
					Severity:    High,
					Title:       "SQL query built with string concatenation",
					Description: "SQL query appears to use string concatenation instead of parameterized queries.",
					File:        str.File,
					StartRow:    str.StartRow,
					StartCol:    str.StartCol,
					EndRow:      str.EndRow,
					EndCol:      str.EndCol,
					Language:    str.Language,
					NodeID:      str.ID,
				})
				break
			}
		}
	}
}

func (e *Engine) addFinding(f Finding) {
	e.counter++
	f.ID = findingID(e.counter)
	e.findings = append(e.findings, f)
}

func findingID(n int) string {
	return "HB-" + padInt(n)
}

func padInt(n int) string {
	s := ""
	if n < 10 {
		s = "000"
	} else if n < 100 {
		s = "00"
	} else if n < 1000 {
		s = "0"
	}
	return s + intToStr(n)
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// FilterBySeverity returns findings at or above the given severity.
func FilterBySeverity(findings []Finding, minSeverity Severity) []Finding {
	order := map[Severity]int{Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0}
	minLevel := order[minSeverity]
	var result []Finding
	for _, f := range findings {
		if order[f.Severity] >= minLevel {
			result = append(result, f)
		}
	}
	return result
}
