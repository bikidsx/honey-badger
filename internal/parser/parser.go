// Package parser provides tree-sitter based AST parsing for source files.
// It wraps gotreesitter (pure Go, no CGO) and exposes a simplified interface
// for extracting function declarations, call expressions, imports, and string
// literals from source code across all Phase 1 languages.
package parser

import (
	"fmt"
	"os"

	"github.com/bikidsx/honey-badger/internal/discovery"
	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// Node represents a simplified AST node extracted from source code.
type Node struct {
	Type     string // tree-sitter node type
	Name     string // extracted name (function name, import path, etc.)
	StartRow int
	StartCol int
	EndRow   int
	EndCol   int
}

// ParseResult holds the parsed output for a single file.
type ParseResult struct {
	Path      string
	Language  discovery.Language
	Functions []Node // function/method declarations
	Calls     []Node // function call expressions
	Imports   []Node // import statements
	Strings   []Node // string literals (for secret detection)
	HasErrors bool   // true if the parse tree contains errors
}

// langToFilename maps our Language to a representative filename for grammar detection.
var langToFilename = map[discovery.Language]string{
	discovery.Python:     "file.py",
	discovery.JavaScript: "file.js",
	discovery.TypeScript: "file.ts",
	discovery.Go:         "file.go",
	discovery.SQL:        "file.sql",
	discovery.YAML:       "file.yaml",
	discovery.JSON:       "file.json",
	discovery.HCL:        "file.tf",
	discovery.Dockerfile: "Dockerfile",
	discovery.Java:       "file.java",
	discovery.CSharp:     "file.cs",
	discovery.Rust:       "file.rs",
	discovery.PHP:        "file.php",
}

// langToGrammarFunc maps our Language to the gotreesitter grammar loader.
var langToGrammarFunc = map[discovery.Language]func() *gotreesitter.Language{
	discovery.Python:     grammars.PythonLanguage,
	discovery.JavaScript: grammars.JavascriptLanguage,
	discovery.TypeScript: grammars.TypescriptLanguage,
	discovery.Go:         grammars.GoLanguage,
	discovery.SQL:        grammars.SqlLanguage,
	discovery.YAML:       grammars.YamlLanguage,
	discovery.JSON:       grammars.JsonLanguage,
	discovery.HCL:        grammars.HclLanguage,
	discovery.Dockerfile: grammars.DockerfileLanguage,
	discovery.Java:       grammars.JavaLanguage,
	discovery.CSharp:     grammars.CSharpLanguage,
	discovery.Rust:       grammars.RustLanguage,
	discovery.PHP:        grammars.PhpLanguage,
}

// queryMap holds tree-sitter S-expression queries per language.
var queryMap = map[discovery.Language]languageQueries{
	discovery.Python: {
		functions: `[(function_definition name: (identifier) @name) (class_definition name: (identifier) @name)]`,
		calls:     `(call function: [(identifier) @name (attribute attribute: (identifier) @name)])`,
		imports:   `[(import_statement name: (dotted_name) @name) (import_from_statement module_name: (dotted_name) @name)]`,
		strings:   `(string) @str`,
	},
	discovery.JavaScript: {
		functions: `[(function_declaration name: (identifier) @name) (method_definition name: (property_identifier) @name)]`,
		calls:     `(call_expression function: [(identifier) @name (member_expression property: (property_identifier) @name)])`,
		imports:   `(import_statement source: (string) @name)`,
		strings:   `(string) @str`,
	},
	discovery.TypeScript: {
		functions: `[(function_declaration name: (identifier) @name) (method_definition name: (property_identifier) @name)]`,
		calls:     `(call_expression function: [(identifier) @name (member_expression property: (property_identifier) @name)])`,
		imports:   `(import_statement source: (string) @name)`,
		strings:   `(string) @str`,
	},
	discovery.Go: {
		functions: `[(function_declaration name: (identifier) @name) (method_declaration name: (field_identifier) @name)]`,
		calls:     `(call_expression function: [(identifier) @name (selector_expression field: (field_identifier) @name)])`,
		imports:   `(import_spec path: (interpreted_string_literal) @name)`,
		strings:   `[(interpreted_string_literal) @str (raw_string_literal) @str]`,
	},
	discovery.Java: {
		functions: `[(method_declaration name: (identifier) @name) (constructor_declaration name: (identifier) @name)]`,
		calls:     `(method_invocation name: (identifier) @name)`,
		imports:   `(import_declaration (scoped_identifier) @name)`,
		strings:   `(string_literal) @str`,
	},
	discovery.CSharp: {
		functions: `[(method_declaration name: (identifier) @name) (constructor_declaration name: (identifier) @name)]`,
		calls:     `(invocation_expression function: [(identifier) @name (member_access_expression name: (identifier) @name)])`,
		imports:   `(using_directive (identifier) @name)`,
		strings:   `(string_literal) @str`,
	},
	discovery.Rust: {
		functions: `(function_item name: (identifier) @name)`,
		calls:     `(call_expression function: [(identifier) @name (field_expression field: (field_identifier) @name)])`,
		imports:   `(use_declaration argument: (_) @name)`,
		strings:   `(string_literal) @str`,
	},
	discovery.PHP: {
		functions: `[(function_definition name: (name) @name) (method_declaration name: (name) @name)]`,
		calls:     `(function_call_expression function: [(name) @name (member_call_expression name: (name) @name)])`,
		imports:   `(namespace_use_clause (qualified_name) @name)`,
		strings:   `[(string) @str (encapsed_string) @str]`,
	},
}

type languageQueries struct {
	functions string
	calls     string
	imports   string
	strings   string
}

// ParseFile parses a single source file and extracts structural information.
func ParseFile(path string, lang discovery.Language) (*ParseResult, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return ParseSource(path, lang, src)
}

// ParseSource parses source code bytes and extracts structural information.
func ParseSource(path string, lang discovery.Language, src []byte) (*ParseResult, error) {
	grammarFunc, ok := langToGrammarFunc[lang]
	if !ok {
		return nil, fmt.Errorf("unsupported language: %s", lang)
	}

	tsLang := grammarFunc()

	// Use the filename hint for grammar detection via ParseFile
	filename := langToFilename[lang]
	bt, err := grammars.ParseFile(filename, src)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	defer bt.Release()

	root := bt.RootNode()
	result := &ParseResult{
		Path:     path,
		Language: lang,
	}

	if root != nil {
		result.HasErrors = root.HasError()
	}

	queries, hasQueries := queryMap[lang]
	if !hasQueries {
		return result, nil
	}

	if queries.functions != "" {
		nodes, err := runQuery(queries.functions, tsLang, root, src)
		if err == nil {
			result.Functions = nodes
		}
	}
	if queries.calls != "" {
		nodes, err := runQuery(queries.calls, tsLang, root, src)
		if err == nil {
			result.Calls = nodes
		}
	}
	if queries.imports != "" {
		nodes, err := runQuery(queries.imports, tsLang, root, src)
		if err == nil {
			result.Imports = nodes
		}
	}
	if queries.strings != "" {
		nodes, err := runQuery(queries.strings, tsLang, root, src)
		if err == nil {
			result.Strings = nodes
		}
	}

	return result, nil
}

// runQuery executes a tree-sitter query and returns extracted nodes.
func runQuery(pattern string, lang *gotreesitter.Language, root *gotreesitter.Node, src []byte) ([]Node, error) {
	if root == nil {
		return nil, nil
	}

	q, err := gotreesitter.NewQuery(pattern, lang)
	if err != nil {
		return nil, fmt.Errorf("compile query: %w", err)
	}

	cursor := q.Exec(root, lang, src)
	var nodes []Node

	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}
		for _, cap := range match.Captures {
			n := cap.Node
			sp := n.StartPoint()
			ep := n.EndPoint()
			nodes = append(nodes, Node{
				Type:     n.Type(lang),
				Name:     n.Text(src),
				StartRow: int(sp.Row),
				StartCol: int(sp.Column),
				EndRow:   int(ep.Row),
				EndCol:   int(ep.Column),
			})
		}
	}
	return nodes, nil
}

// SupportedForParsing returns languages that have tree-sitter grammars available.
func SupportedForParsing() []discovery.Language {
	var supported []discovery.Language
	for lang := range langToGrammarFunc {
		supported = append(supported, lang)
	}
	return supported
}
