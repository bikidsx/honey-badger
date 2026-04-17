// Package cpg implements a Code Property Graph that merges AST information
// from parsed source files into a unified queryable graph. Nodes represent
// functions, calls, imports, and string literals. Edges represent call
// relationships, data flow, and cross-file references.
package cpg

import (
	"fmt"
	"strings"

	"github.com/bikidsx/honey-badger/internal/discovery"
	"github.com/bikidsx/honey-badger/internal/parser"
)

// NodeKind classifies CPG nodes.
type NodeKind string

const (
	KindFunction NodeKind = "function"
	KindCall     NodeKind = "call"
	KindImport   NodeKind = "import"
	KindString   NodeKind = "string"
	KindFile     NodeKind = "file"
)

// EdgeKind classifies CPG edges.
type EdgeKind string

const (
	EdgeCalls    EdgeKind = "calls"    // function A calls function B
	EdgeDefinedIn EdgeKind = "defined_in" // function defined in file
	EdgeImports  EdgeKind = "imports"  // file imports module
	EdgeContains EdgeKind = "contains" // file contains string/call
)

// NodeID uniquely identifies a node in the graph.
type NodeID string

// CPGNode represents a node in the Code Property Graph.
type CPGNode struct {
	ID       NodeID
	Kind     NodeKind
	Name     string             // function name, import path, string value, file path
	File     string             // source file path
	Language discovery.Language
	StartRow int
	StartCol int
	EndRow   int
	EndCol   int
}

// CPGEdge represents a directed edge in the Code Property Graph.
type CPGEdge struct {
	From NodeID
	To   NodeID
	Kind EdgeKind
}

// Graph is the Code Property Graph.
type Graph struct {
	Nodes map[NodeID]*CPGNode
	Edges []CPGEdge

	// Indexes for fast lookup.
	funcsByName map[string][]*CPGNode // function name -> nodes
	fileNodes   map[string]*CPGNode   // file path -> file node
}

// NewGraph creates an empty CPG.
func NewGraph() *Graph {
	return &Graph{
		Nodes:       make(map[NodeID]*CPGNode),
		funcsByName: make(map[string][]*CPGNode),
		fileNodes:   make(map[string]*CPGNode),
	}
}

// AddNode adds a node to the graph.
func (g *Graph) AddNode(n *CPGNode) {
	g.Nodes[n.ID] = n
	if n.Kind == KindFunction {
		g.funcsByName[n.Name] = append(g.funcsByName[n.Name], n)
	}
	if n.Kind == KindFile {
		g.fileNodes[n.Name] = n
	}
}

// AddEdge adds a directed edge to the graph.
func (g *Graph) AddEdge(from, to NodeID, kind EdgeKind) {
	g.Edges = append(g.Edges, CPGEdge{From: from, To: to, Kind: kind})
}

// FunctionsByName returns all function nodes with the given name.
func (g *Graph) FunctionsByName(name string) []*CPGNode {
	return g.funcsByName[name]
}

// CallsFrom returns all call edges originating from a given node.
func (g *Graph) CallsFrom(id NodeID) []*CPGNode {
	var targets []*CPGNode
	for _, e := range g.Edges {
		if e.From == id && e.Kind == EdgeCalls {
			if n, ok := g.Nodes[e.To]; ok {
				targets = append(targets, n)
			}
		}
	}
	return targets
}

// CallersOf returns all nodes that call the given function.
func (g *Graph) CallersOf(id NodeID) []*CPGNode {
	var callers []*CPGNode
	for _, e := range g.Edges {
		if e.To == id && e.Kind == EdgeCalls {
			if n, ok := g.Nodes[e.From]; ok {
				callers = append(callers, n)
			}
		}
	}
	return callers
}

// NodesOfKind returns all nodes of a given kind.
func (g *Graph) NodesOfKind(kind NodeKind) []*CPGNode {
	var result []*CPGNode
	for _, n := range g.Nodes {
		if n.Kind == kind {
			result = append(result, n)
		}
	}
	return result
}

// Build constructs a CPG from a set of parse results. It creates nodes for
// all extracted elements and resolves call edges within the same language
// by matching call names to function definitions.
func Build(results []*parser.ParseResult) *Graph {
	g := NewGraph()

	for _, pr := range results {
		fileID := NodeID(fmt.Sprintf("file:%s", pr.Path))
		g.AddNode(&CPGNode{
			ID:       fileID,
			Kind:     KindFile,
			Name:     pr.Path,
			File:     pr.Path,
			Language: pr.Language,
		})

		for i, fn := range pr.Functions {
			fnID := NodeID(fmt.Sprintf("func:%s:%s:%d", pr.Path, fn.Name, i))
			g.AddNode(&CPGNode{
				ID:       fnID,
				Kind:     KindFunction,
				Name:     fn.Name,
				File:     pr.Path,
				Language: pr.Language,
				StartRow: fn.StartRow,
				StartCol: fn.StartCol,
				EndRow:   fn.EndRow,
				EndCol:   fn.EndCol,
			})
			g.AddEdge(fnID, fileID, EdgeDefinedIn)
		}

		for i, call := range pr.Calls {
			callID := NodeID(fmt.Sprintf("call:%s:%s:%d", pr.Path, call.Name, i))
			g.AddNode(&CPGNode{
				ID:       callID,
				Kind:     KindCall,
				Name:     call.Name,
				File:     pr.Path,
				Language: pr.Language,
				StartRow: call.StartRow,
				StartCol: call.StartCol,
				EndRow:   call.EndRow,
				EndCol:   call.EndCol,
			})
			g.AddEdge(callID, fileID, EdgeContains)
		}

		for i, imp := range pr.Imports {
			impID := NodeID(fmt.Sprintf("import:%s:%s:%d", pr.Path, imp.Name, i))
			g.AddNode(&CPGNode{
				ID:       impID,
				Kind:     KindImport,
				Name:     imp.Name,
				File:     pr.Path,
				Language: pr.Language,
				StartRow: imp.StartRow,
				StartCol: imp.StartCol,
				EndRow:   imp.EndRow,
				EndCol:   imp.EndCol,
			})
			g.AddEdge(fileID, impID, EdgeImports)
		}

		for i, str := range pr.Strings {
			strID := NodeID(fmt.Sprintf("str:%s:%d", pr.Path, i))
			g.AddNode(&CPGNode{
				ID:       strID,
				Kind:     KindString,
				Name:     str.Name,
				File:     pr.Path,
				Language: pr.Language,
				StartRow: str.StartRow,
				StartCol: str.StartCol,
				EndRow:   str.EndRow,
				EndCol:   str.EndCol,
			})
			g.AddEdge(strID, fileID, EdgeContains)
		}
	}

	// Resolve call edges: match call nodes to function definition nodes.
	resolveCallEdges(g)

	return g
}

// resolveCallEdges matches call nodes to function definitions by name.
// This handles single-language cross-file resolution.
func resolveCallEdges(g *Graph) {
	callNodes := g.NodesOfKind(KindCall)
	for _, call := range callNodes {
		targets := g.funcsByName[call.Name]
		for _, target := range targets {
			// Only resolve within the same language for Phase 1.
			if target.Language == call.Language {
				g.AddEdge(call.ID, target.ID, EdgeCalls)
			}
		}
	}
}

// Stats returns summary statistics about the graph.
func (g *Graph) Stats() map[string]int {
	stats := map[string]int{
		"nodes":     len(g.Nodes),
		"edges":     len(g.Edges),
		"files":     len(g.fileNodes),
		"functions": len(g.NodesOfKind(KindFunction)),
		"calls":     len(g.NodesOfKind(KindCall)),
		"imports":   len(g.NodesOfKind(KindImport)),
		"strings":   len(g.NodesOfKind(KindString)),
	}

	// Count resolved call edges.
	resolved := 0
	for _, e := range g.Edges {
		if e.Kind == EdgeCalls {
			resolved++
		}
	}
	stats["resolved_calls"] = resolved
	return stats
}

// FindReachable returns all nodes reachable from the given node via edges of
// the specified kinds. Uses BFS. Useful for taint tracking.
func (g *Graph) FindReachable(start NodeID, edgeKinds ...EdgeKind) []*CPGNode {
	kindSet := make(map[EdgeKind]bool, len(edgeKinds))
	for _, k := range edgeKinds {
		kindSet[k] = true
	}

	visited := make(map[NodeID]bool)
	queue := []NodeID{start}
	visited[start] = true
	var result []*CPGNode

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, e := range g.Edges {
			if e.From == current && kindSet[e.Kind] && !visited[e.To] {
				visited[e.To] = true
				queue = append(queue, e.To)
				if n, ok := g.Nodes[e.To]; ok {
					result = append(result, n)
				}
			}
		}
	}
	return result
}

// StringsContaining returns all string nodes whose value contains the substring.
func (g *Graph) StringsContaining(substr string) []*CPGNode {
	var result []*CPGNode
	for _, n := range g.Nodes {
		if n.Kind == KindString && strings.Contains(n.Name, substr) {
			result = append(result, n)
		}
	}
	return result
}
