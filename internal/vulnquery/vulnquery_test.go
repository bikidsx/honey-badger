package vulnquery

import (
	"testing"

	"github.com/bikidas/honey-badger/internal/cpg"
	"github.com/bikidas/honey-badger/internal/discovery"
	"github.com/bikidas/honey-badger/internal/parser"
)

func buildTestGraph(results []*parser.ParseResult) *cpg.Graph {
	return cpg.Build(results)
}

func TestDetectSQLInjectionSink(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "db.py",
			Language: discovery.Python,
			Calls: []parser.Node{
				{Name: "execute", StartRow: 5, StartCol: 4},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	found := findByClass(findings, SQLInjection)
	if len(found) == 0 {
		t.Error("expected SQL injection finding for execute() call")
	}
}

func TestDetectCommandInjection(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "handler.py",
			Language: discovery.Python,
			Calls: []parser.Node{
				{Name: "popen", StartRow: 10, StartCol: 8},
				{Name: "system", StartRow: 12, StartCol: 4},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	found := findByClass(findings, CommandInjection)
	if len(found) < 2 {
		t.Errorf("expected at least 2 command injection findings, got %d", len(found))
	}
	for _, f := range found {
		if f.Severity != Critical {
			t.Errorf("command injection should be critical, got %s", f.Severity)
		}
	}
}

func TestDetectSSRF(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "api.js",
			Language: discovery.JavaScript,
			Calls: []parser.Node{
				{Name: "fetch", StartRow: 3, StartCol: 4},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	found := findByClass(findings, SSRF)
	if len(found) == 0 {
		t.Error("expected SSRF finding for fetch() call")
	}
}

func TestDetectXSS(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "render.js",
			Language: discovery.JavaScript,
			Calls: []parser.Node{
				{Name: "innerHTML", StartRow: 7, StartCol: 4},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	found := findByClass(findings, XSS)
	if len(found) == 0 {
		t.Error("expected XSS finding for innerHTML")
	}
}

func TestDetectGoSinks(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "main.go",
			Language: discovery.Go,
			Calls: []parser.Node{
				{Name: "Query", StartRow: 15, StartCol: 4},
				{Name: "Command", StartRow: 20, StartCol: 4},
				{Name: "Get", StartRow: 25, StartCol: 4},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	if len(findByClass(findings, SQLInjection)) == 0 {
		t.Error("expected SQL injection finding for Query()")
	}
	if len(findByClass(findings, CommandInjection)) == 0 {
		t.Error("expected command injection finding for Command()")
	}
	if len(findByClass(findings, SSRF)) == 0 {
		t.Error("expected SSRF finding for Get()")
	}
}

func TestDetectHardcodedPassword(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "config.py",
			Language: discovery.Python,
			Strings: []parser.Node{
				{Name: `password = "supersecret123"`, StartRow: 3, StartCol: 0},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	found := findByClass(findings, HardcodedSecret)
	if len(found) == 0 {
		t.Error("expected hardcoded secret finding for password")
	}
}

func TestDetectAWSKey(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "deploy.py",
			Language: discovery.Python,
			Strings: []parser.Node{
				{Name: `"AKIAIOSFODNN7EXAMPLE"`, StartRow: 1, StartCol: 0},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	found := findByClass(findings, HardcodedSecret)
	if len(found) == 0 {
		t.Error("expected hardcoded secret finding for AWS key")
	}
	if len(found) > 0 && found[0].Severity != Critical {
		t.Errorf("AWS key should be critical, got %s", found[0].Severity)
	}
}

func TestDetectGitHubToken(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "ci.py",
			Language: discovery.Python,
			Strings: []parser.Node{
				{Name: `"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"`, StartRow: 2, StartCol: 0},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	found := findByClass(findings, HardcodedSecret)
	if len(found) == 0 {
		t.Error("expected hardcoded secret finding for GitHub token")
	}
}

func TestDetectSQLStringConcat(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "db.py",
			Language: discovery.Python,
			Strings: []parser.Node{
				{Name: `"SELECT * FROM users WHERE id = " + user_input`, StartRow: 5, StartCol: 4},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	found := findByClass(findings, SQLInjection)
	if len(found) == 0 {
		t.Error("expected SQL injection finding for string concatenation")
	}
}

func TestNoFalsePositiveOnSafeString(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "safe.py",
			Language: discovery.Python,
			Strings: []parser.Node{
				{Name: `"Hello, World!"`, StartRow: 1, StartCol: 0},
				{Name: `"Welcome to the app"`, StartRow: 2, StartCol: 0},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe strings, got %d", len(findings))
	}
}

func TestRunFocused(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "app.py",
			Language: discovery.Python,
			Calls: []parser.Node{
				{Name: "execute", StartRow: 5},  // SQL injection
				{Name: "popen", StartRow: 10},    // Command injection
			},
			Strings: []parser.Node{
				{Name: `password = "secret123"`, StartRow: 1},
			},
		},
	})

	e := NewEngine(g)

	// Only check SQL injection
	findings := e.RunFocused(SQLInjection)
	for _, f := range findings {
		if f.Class != SQLInjection {
			t.Errorf("focused run should only return SQLInjection, got %s", f.Class)
		}
	}

	// Only check secrets
	e2 := NewEngine(g)
	secretFindings := e2.RunFocused(HardcodedSecret)
	for _, f := range secretFindings {
		if f.Class != HardcodedSecret {
			t.Errorf("focused run should only return HardcodedSecret, got %s", f.Class)
		}
	}
}

func TestFilterBySeverity(t *testing.T) {
	findings := []Finding{
		{Severity: Critical, Class: CommandInjection},
		{Severity: High, Class: SQLInjection},
		{Severity: Medium, Class: XSS},
		{Severity: Low, Class: PathTraversal},
		{Severity: Info},
	}

	critical := FilterBySeverity(findings, Critical)
	if len(critical) != 1 {
		t.Errorf("expected 1 critical finding, got %d", len(critical))
	}

	high := FilterBySeverity(findings, High)
	if len(high) != 2 {
		t.Errorf("expected 2 high+ findings, got %d", len(high))
	}

	medium := FilterBySeverity(findings, Medium)
	if len(medium) != 3 {
		t.Errorf("expected 3 medium+ findings, got %d", len(medium))
	}

	all := FilterBySeverity(findings, Info)
	if len(all) != 5 {
		t.Errorf("expected 5 info+ findings, got %d", len(all))
	}
}

func TestFindingIDs(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "app.py",
			Language: discovery.Python,
			Calls: []parser.Node{
				{Name: "execute", StartRow: 1},
				{Name: "popen", StartRow: 2},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	ids := make(map[string]bool)
	for _, f := range findings {
		if f.ID == "" {
			t.Error("finding has empty ID")
		}
		if ids[f.ID] {
			t.Errorf("duplicate finding ID: %s", f.ID)
		}
		ids[f.ID] = true
	}
}

func TestFindingFileAndPosition(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "handler.py",
			Language: discovery.Python,
			Calls: []parser.Node{
				{Name: "execute", StartRow: 42, StartCol: 8, EndRow: 42, EndCol: 30},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	f := findings[0]
	if f.File != "handler.py" {
		t.Errorf("expected file handler.py, got %s", f.File)
	}
	if f.StartRow != 42 {
		t.Errorf("expected StartRow 42, got %d", f.StartRow)
	}
	if f.Language != discovery.Python {
		t.Errorf("expected Python, got %s", f.Language)
	}
}

func TestEmptyGraphNoFindings(t *testing.T) {
	g := cpg.NewGraph()
	e := NewEngine(g)
	findings := e.Run()
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on empty graph, got %d", len(findings))
	}
}

func TestCrossLanguageSinkIsolation(t *testing.T) {
	// Python's "execute" should not trigger on Go code
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "main.go",
			Language: discovery.Go,
			Calls: []parser.Node{
				{Name: "execute", StartRow: 5}, // not a Go sink
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	// "execute" is a Python sink, not a Go sink
	for _, f := range findings {
		if f.Class == SQLInjection && f.Language == discovery.Go {
			t.Error("execute should not be flagged as SQL injection in Go")
		}
	}
}

func TestPathTraversalDetection(t *testing.T) {
	g := buildTestGraph([]*parser.ParseResult{
		{
			Path:     "files.go",
			Language: discovery.Go,
			Calls: []parser.Node{
				{Name: "Open", StartRow: 10, StartCol: 4},
				{Name: "ReadFile", StartRow: 15, StartCol: 4},
			},
		},
	})

	e := NewEngine(g)
	findings := e.Run()

	found := findByClass(findings, PathTraversal)
	if len(found) < 2 {
		t.Errorf("expected at least 2 path traversal findings, got %d", len(found))
	}
}

// helper
func findByClass(findings []Finding, class VulnClass) []Finding {
	var result []Finding
	for _, f := range findings {
		if f.Class == class {
			result = append(result, f)
		}
	}
	return result
}
