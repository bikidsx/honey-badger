package cpg

import (
	"testing"

	"github.com/bikidas/honey-badger/internal/discovery"
	"github.com/bikidas/honey-badger/internal/parser"
)

func sampleParseResults() []*parser.ParseResult {
	return []*parser.ParseResult{
		{
			Path:     "handler.py",
			Language: discovery.Python,
			Functions: []parser.Node{
				{Name: "handle_request", StartRow: 3, StartCol: 0, EndRow: 5, EndCol: 20},
				{Name: "validate_input", StartRow: 7, StartCol: 0, EndRow: 9, EndCol: 15},
			},
			Calls: []parser.Node{
				{Name: "validate_input", StartRow: 4, StartCol: 4},
				{Name: "popen", StartRow: 5, StartCol: 4},
			},
			Imports: []parser.Node{
				{Name: "os", StartRow: 0, StartCol: 0},
			},
			Strings: []parser.Node{
				{Name: `"SELECT * FROM users WHERE id = "`, StartRow: 4, StartCol: 12},
			},
		},
		{
			Path:     "utils.py",
			Language: discovery.Python,
			Functions: []parser.Node{
				{Name: "sanitize", StartRow: 1, StartCol: 0, EndRow: 3, EndCol: 10},
			},
			Calls: []parser.Node{
				{Name: "handle_request", StartRow: 5, StartCol: 0},
			},
			Imports: []parser.Node{
				{Name: "handler", StartRow: 0, StartCol: 0},
			},
			Strings: []parser.Node{
				{Name: `"password123"`, StartRow: 2, StartCol: 8},
			},
		},
	}
}

func TestBuildGraph(t *testing.T) {
	g := Build(sampleParseResults())

	if len(g.Nodes) == 0 {
		t.Fatal("expected nodes in graph")
	}
	if len(g.Edges) == 0 {
		t.Fatal("expected edges in graph")
	}
}

func TestGraphStats(t *testing.T) {
	g := Build(sampleParseResults())
	stats := g.Stats()

	if stats["files"] != 2 {
		t.Errorf("expected 2 files, got %d", stats["files"])
	}
	if stats["functions"] != 3 {
		t.Errorf("expected 3 functions, got %d", stats["functions"])
	}
	if stats["calls"] != 3 {
		t.Errorf("expected 3 calls, got %d", stats["calls"])
	}
	if stats["imports"] != 2 {
		t.Errorf("expected 2 imports, got %d", stats["imports"])
	}
	if stats["strings"] != 2 {
		t.Errorf("expected 2 strings, got %d", stats["strings"])
	}
}

func TestFunctionsByName(t *testing.T) {
	g := Build(sampleParseResults())

	fns := g.FunctionsByName("handle_request")
	if len(fns) != 1 {
		t.Fatalf("expected 1 function named handle_request, got %d", len(fns))
	}
	if fns[0].File != "handler.py" {
		t.Errorf("expected function in handler.py, got %s", fns[0].File)
	}
}

func TestCallEdgeResolution(t *testing.T) {
	g := Build(sampleParseResults())

	// "validate_input" call in handler.py should resolve to the function definition
	stats := g.Stats()
	if stats["resolved_calls"] == 0 {
		t.Error("expected at least one resolved call edge")
	}

	// Check that validate_input call resolves to validate_input function
	fns := g.FunctionsByName("validate_input")
	if len(fns) == 0 {
		t.Fatal("expected validate_input function")
	}
	callers := g.CallersOf(fns[0].ID)
	if len(callers) == 0 {
		t.Error("expected callers of validate_input")
	}
}

func TestCrossFileCallResolution(t *testing.T) {
	g := Build(sampleParseResults())

	// "handle_request" call in utils.py should resolve to function in handler.py
	fns := g.FunctionsByName("handle_request")
	if len(fns) == 0 {
		t.Fatal("expected handle_request function")
	}
	callers := g.CallersOf(fns[0].ID)
	found := false
	for _, c := range callers {
		if c.File == "utils.py" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected cross-file call from utils.py to handle_request in handler.py")
	}
}

func TestCallsFrom(t *testing.T) {
	g := Build(sampleParseResults())

	// Find a call node for validate_input
	var callNode *CPGNode
	for _, n := range g.Nodes {
		if n.Kind == KindCall && n.Name == "validate_input" {
			callNode = n
			break
		}
	}
	if callNode == nil {
		t.Fatal("expected validate_input call node")
	}

	targets := g.CallsFrom(callNode.ID)
	if len(targets) == 0 {
		t.Error("expected call targets for validate_input")
	}
	if targets[0].Name != "validate_input" {
		t.Errorf("expected target name validate_input, got %s", targets[0].Name)
	}
}

func TestNodesOfKind(t *testing.T) {
	g := Build(sampleParseResults())

	tests := []struct {
		kind NodeKind
		min  int
	}{
		{KindFile, 2},
		{KindFunction, 3},
		{KindCall, 3},
		{KindImport, 2},
		{KindString, 2},
	}

	for _, tt := range tests {
		nodes := g.NodesOfKind(tt.kind)
		if len(nodes) < tt.min {
			t.Errorf("NodesOfKind(%s): expected at least %d, got %d", tt.kind, tt.min, len(nodes))
		}
	}
}

func TestStringsContaining(t *testing.T) {
	g := Build(sampleParseResults())

	// Should find the SQL string
	sqlStrings := g.StringsContaining("SELECT")
	if len(sqlStrings) == 0 {
		t.Error("expected to find string containing SELECT")
	}

	// Should find the password string
	pwStrings := g.StringsContaining("password")
	if len(pwStrings) == 0 {
		t.Error("expected to find string containing password")
	}

	// Should not find nonexistent string
	none := g.StringsContaining("nonexistent_xyz_123")
	if len(none) != 0 {
		t.Errorf("expected 0 results, got %d", len(none))
	}
}

func TestFindReachable(t *testing.T) {
	g := Build(sampleParseResults())

	// Find a call node and check reachability via call edges
	var callNode *CPGNode
	for _, n := range g.Nodes {
		if n.Kind == KindCall && n.Name == "validate_input" {
			callNode = n
			break
		}
	}
	if callNode == nil {
		t.Fatal("expected validate_input call node")
	}

	reachable := g.FindReachable(callNode.ID, EdgeCalls)
	if len(reachable) == 0 {
		t.Error("expected reachable nodes from validate_input call")
	}
}

func TestEmptyGraph(t *testing.T) {
	g := Build(nil)
	stats := g.Stats()
	if stats["nodes"] != 0 {
		t.Errorf("expected 0 nodes, got %d", stats["nodes"])
	}
}

func TestBuildWithEmptyParseResult(t *testing.T) {
	results := []*parser.ParseResult{
		{
			Path:     "empty.py",
			Language: discovery.Python,
		},
	}
	g := Build(results)
	stats := g.Stats()
	if stats["files"] != 1 {
		t.Errorf("expected 1 file node, got %d", stats["files"])
	}
	if stats["functions"] != 0 {
		t.Errorf("expected 0 functions, got %d", stats["functions"])
	}
}

func TestNodePositionsPreserved(t *testing.T) {
	g := Build(sampleParseResults())
	fns := g.FunctionsByName("handle_request")
	if len(fns) == 0 {
		t.Fatal("expected handle_request")
	}
	fn := fns[0]
	if fn.StartRow != 3 {
		t.Errorf("expected StartRow=3, got %d", fn.StartRow)
	}
	if fn.EndRow != 5 {
		t.Errorf("expected EndRow=5, got %d", fn.EndRow)
	}
}

func TestLanguagePreserved(t *testing.T) {
	g := Build(sampleParseResults())
	for _, n := range g.Nodes {
		if n.Language != discovery.Python {
			t.Errorf("expected Python language, got %s for node %s", n.Language, n.ID)
		}
	}
}

func TestMultiLanguageNoResolution(t *testing.T) {
	// Functions with same name in different languages should NOT resolve
	results := []*parser.ParseResult{
		{
			Path:     "app.py",
			Language: discovery.Python,
			Functions: []parser.Node{
				{Name: "process", StartRow: 0},
			},
		},
		{
			Path:     "app.go",
			Language: discovery.Go,
			Calls: []parser.Node{
				{Name: "process", StartRow: 5},
			},
		},
	}
	g := Build(results)

	// The Go call to "process" should NOT resolve to the Python function
	stats := g.Stats()
	if stats["resolved_calls"] != 0 {
		t.Errorf("expected 0 cross-language resolved calls, got %d", stats["resolved_calls"])
	}
}
