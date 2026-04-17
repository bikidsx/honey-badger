# STEERING.md — Honey Badger Architectural Reference

> This document is the ground truth for how Honey Badger is built, why decisions were made, and how to extend it. Read this before making changes.

---

## Identity

**Honey Badger** (`hb`) is a repository-level, language-agnostic, semantics-first codebase security analysis CLI. It builds a Code Property Graph from an entire codebase and finds vulnerabilities that span files and functions.

**Module path:** `github.com/bikidas/honey-badger`
**Language:** Go 1.22+ (developed on 1.26.2)
**License:** MIT
**Binary name:** `hb`

---

## Core Principles

1. **Single binary, zero runtime deps.** No CGO. No external tools. `go install` and run.
2. **Polyglot-native.** Multi-language is the default, not an afterthought. The CPG is unified across all languages.
3. **Deterministic first, LLM second.** Pattern matching and graph traversal handle the common cases. LLMs are for reasoning about ambiguous cases, not for basic detection.
4. **Tests are not optional.** Every package has tests. Every new feature ships with tests. The test count should only go up.
5. **Extend, don't rewrite.** New languages = new query patterns, not new parsers. New vuln classes = new sink definitions, not new engines.

---

## Architecture

```
main.go
  └── cmd/              CLI commands (cobra)
        ├── root.go     Root command, global flags
        ├── scan.go     Full pipeline: discover → parse → CPG → vulnquery → report
        ├── understand.go  CPG stats, callgraph, entrypoints
        ├── info.go     Language detection summary
        └── version.go  Version string (set via ldflags)

internal/
  ├── discovery/        File walking + language detection
  ├── parser/           Tree-sitter AST extraction
  ├── cpg/              Code Property Graph
  ├── vulnquery/        Vulnerability detection engine
  └── report/           SARIF, JSON, Markdown output
```

### Data flow (scan pipeline)

```
Directory path
    │
    ▼
discovery.Scan()          → []SourceFile (path, language, size)
    │
    ▼
parser.ParseFile()        → []ParseResult (functions, calls, imports, strings per file)
    │
    ▼
cpg.Build()               → *Graph (nodes + edges, call resolution)
    │
    ▼
vulnquery.NewEngine().Run() → []Finding (vuln class, severity, location)
    │
    ▼
report.WriteSARIF()       → SARIF JSON to stdout/file
```

Each step is a pure function of its inputs. No global state. No singletons.

---

## Package Reference

### `internal/discovery`

**Purpose:** Walk a directory tree, detect programming languages by file extension, return a structured inventory.

**Key types:**
- `Language` — string enum: `python`, `javascript`, `typescript`, `go`, `sql`, `yaml`, `json`, `hcl`, `dockerfile`
- `SourceFile` — `{Path, Language, Size}`
- `Result` — `{Root, Files, Stats}`
- `Options` — `{IgnoreDirs, FilterLangs}`

**Key functions:**
- `Scan(root, opts) → (*Result, error)` — main entry point
- `DetectLanguage(path) → Language` — extension-based detection

**Extension point:** To add a new language, add its extensions to `extMap` in discovery.go. That's it.

**Default ignored dirs:** `.git`, `node_modules`, `vendor`, `__pycache__`, `.venv`, `venv`, `dist`, `build`, `.next`, `.cache`, `target`

### `internal/parser`

**Purpose:** Parse source files into ASTs using gotreesitter (pure Go tree-sitter runtime) and extract structural elements.

**Key types:**
- `Node` — `{Type, Name, StartRow, StartCol, EndRow, EndCol}`
- `ParseResult` — `{Path, Language, Functions, Calls, Imports, Strings, HasErrors}`

**Key functions:**
- `ParseFile(path, lang) → (*ParseResult, error)` — reads file and parses
- `ParseSource(path, lang, src) → (*ParseResult, error)` — parses byte slice

**How parsing works:**
1. Map our `Language` to a gotreesitter grammar via `langToGrammarFunc` (e.g., `discovery.Python` → `grammars.PythonLanguage`)
2. Call `grammars.ParseFile(filename, src)` which returns a `*BoundTree`
3. Run tree-sitter S-expression queries from `queryMap` to extract functions, calls, imports, strings
4. Return structured `ParseResult`

**Extension point — adding a new language:**
1. Add the grammar function to `langToGrammarFunc` map
2. Add a representative filename to `langToFilename` map
3. Add S-expression queries to `queryMap` (optional — languages without queries still get parse trees)
4. Add the language to `discovery.extMap`

**Query patterns per language:**

| Language | Functions | Calls | Imports | Strings |
|---|---|---|---|---|
| Python | `function_definition`, `class_definition` | `call` with `identifier`/`attribute` | `import_statement`, `import_from_statement` | `string` |
| JavaScript | `function_declaration`, `method_definition` | `call_expression` | `import_statement` source | `string` |
| TypeScript | Same as JavaScript | Same as JavaScript | Same as JavaScript | `string` |
| Go | `function_declaration`, `method_declaration` | `call_expression` | `import_spec` path | `interpreted_string_literal`, `raw_string_literal` |
| SQL–Dockerfile | No queries | No queries | No queries | No queries |

**Dependency:** `github.com/odvcencio/gotreesitter v0.14.0` — pure Go, no CGO, 206 grammars. The `Node.Type(lang)` method requires passing the `*Language`. The `NewQuery` function takes a `string`, not `[]byte`.

### `internal/cpg`

**Purpose:** Build a Code Property Graph from parse results. The CPG is the central data structure — all analysis operates on it.

**Key types:**
- `NodeKind` — `function`, `call`, `import`, `string`, `file`
- `EdgeKind` — `calls`, `defined_in`, `imports`, `contains`
- `NodeID` — string, format: `"kind:file:name:index"` (e.g., `"func:handler.py:process:0"`)
- `CPGNode` — `{ID, Kind, Name, File, Language, StartRow, StartCol, EndRow, EndCol}`
- `CPGEdge` — `{From, To, Kind}`
- `Graph` — `{Nodes, Edges}` + indexes (`funcsByName`, `fileNodes`)

**Key functions:**
- `Build(results) → *Graph` — constructs CPG from parse results, resolves call edges
- `graph.FunctionsByName(name)` — lookup by function name
- `graph.CallsFrom(id)` / `graph.CallersOf(id)` — call graph traversal
- `graph.NodesOfKind(kind)` — filter by node type
- `graph.FindReachable(start, edgeKinds...)` — BFS reachability (seed for taint tracking)
- `graph.StringsContaining(substr)` — string search (used by secret detection)
- `graph.Stats()` — summary counts

**Call resolution logic:** `resolveCallEdges()` matches call nodes to function definition nodes by name, **within the same language only**. This is the Phase 1 constraint. Phase 2 adds cross-language resolution.

**Performance note:** Edge lookup is O(n) linear scan over all edges. Fine for repos with <100k edges. If this becomes a bottleneck, add an adjacency list index (`map[NodeID][]CPGEdge`).

**Extension points for Phase 2:**
- Add `Confidence float64` to `CPGEdge` for heuristic cross-language edges
- Add new `EdgeKind` values: `EdgeRESTCall`, `EdgeGRPCCall`, `EdgeDBQuery`, `EdgeEnvVar`
- Add `NodeKind` values: `KindRoute`, `KindEndpoint`, `KindEnvVar`
- Modify `resolveCallEdges` to also resolve cross-language edges with confidence scoring

### `internal/vulnquery`

**Purpose:** Pattern-based vulnerability detection over the CPG.

**Key types:**
- `Severity` — `critical`, `high`, `medium`, `low`, `info`
- `VulnClass` — `sql-injection`, `command-injection`, `ssrf`, `xss`, `hardcoded-secret`, `path-traversal`
- `Finding` — `{ID, Class, Severity, Title, Description, File, StartRow, StartCol, EndRow, EndCol, Language, NodeID}`
- `Engine` — holds graph reference, runs checks, collects findings

**Detection mechanisms:**

1. **Sink matching** (`checkSinks`): Matches call nodes against `sinkRegistry` — a list of `{Language, Names, Class, Severity}` tuples. A call to `execute()` in Python triggers SQL injection. A call to `Command()` in Go triggers command injection. Language-scoped — Python sinks don't fire on Go code.

2. **Secret detection** (`checkSecrets`): Matches string literal nodes against `secretPatterns` — compiled regexes for passwords, API keys, AWS keys, GitHub tokens, private keys, connection strings.

3. **SQL concatenation** (`checkSQLStringConcat`): Matches string nodes containing SQL keywords (`SELECT`, `INSERT`, etc.) AND concatenation indicators (`+`, `.format(`, `f"`, etc.).

**Key functions:**
- `engine.Run() → []Finding` — runs all checks
- `engine.RunFocused(classes...) → []Finding` — runs only specified vuln classes
- `FilterBySeverity(findings, minSeverity) → []Finding` — for CI mode

**Extension point — adding a new vuln class:**
1. Add a `VulnClass` constant
2. Add sink definitions to `sinkRegistry` (for sink-based detection)
3. Or add a new `check*` method and call it from `Run()`
4. Add tests

**Extension point — adding a new language to existing vuln classes:**
Add entries to `sinkRegistry` with the new language and its dangerous function names.

### `internal/report`

**Purpose:** Serialize findings into output formats.

**Formats:**
- **SARIF v2.1.0** — `WriteSARIF(w, findings, version)`. Proper schema URI, 1-based line numbers, rule deduplication, tool metadata.
- **JSON** — `WriteJSON(w, findings)`. Raw finding array.
- **Markdown** — `WriteMarkdown(w, findings)`. Severity summary table + finding details.

**SARIF notes:** Line numbers are converted from 0-based (internal) to 1-based (SARIF spec). Rules are deduplicated by `VulnClass`. Severity mapping: critical/high → "error", medium → "warning", low/info → "note".

### `cmd/`

**Purpose:** CLI commands using cobra.

**Commands:**
- `hb scan <path>` — full pipeline, outputs report
- `hb understand <path>` — CPG stats, `--show=callgraph|entrypoints`
- `hb info <path>` — language detection summary
- `hb version` — prints version string

**Global flags:** `-o`/`--output` (sarif|json|markdown)
**Scan flags:** `--focus`, `--langs`, `--ci`, `--fail-on`

**Testing pattern:** All commands use `cmd.Print`/`cmd.Printf` (not `fmt.Print`) so output goes through cobra's writer, which tests can capture via `rootCmd.SetOut(buf)`.

---

## Dependencies

| Dependency | Version | Purpose | CGO? |
|---|---|---|---|
| `github.com/spf13/cobra` | v1.9.1 | CLI framework | No |
| `github.com/odvcencio/gotreesitter` | v0.14.0 | Tree-sitter parsing (pure Go) | **No** |
| `github.com/spf13/pflag` | v1.0.6 | Flag parsing (cobra dep) | No |
| `github.com/inconshreveable/mousetrap` | v1.1.0 | Windows console (cobra dep) | No |

**No CGO.** This is a hard constraint. The binary must cross-compile to any GOOS/GOARCH without a C toolchain. gotreesitter was chosen specifically because it's a pure Go tree-sitter runtime (vs smacker/go-tree-sitter which requires CGO).

---

## Testing Strategy

**Rule:** Every package has `*_test.go`. Every new feature ships with tests.

| Package | Test file | Test count | What's tested |
|---|---|---|---|
| `cmd/` | `cmd_test.go` | 15 | Command execution, flag parsing, output format, pipeline integration |
| `internal/discovery/` | `discovery_test.go` | 35 subtests | Language detection (24 extensions), directory walking, filtering, ignore dirs, edge cases |
| `internal/parser/` | `parser_test.go` | 16 | All 9 languages, malformed code, empty files, positions, file I/O |
| `internal/cpg/` | `cpg_test.go` | 14 | Graph building, call resolution, cross-file edges, multi-language isolation, BFS reachability |
| `internal/vulnquery/` | `vulnquery_test.go` | 17 | All 6 vuln classes, secret patterns, false positive checks, severity filtering, focused scans |
| `internal/report/` | `report_test.go` | 10 | SARIF validity, field correctness, rule dedup, empty findings, markdown format |
| `test/` | `integration_test.go` | 5 | Full pipeline end-to-end, SARIF output, language filtering, focused scan, severity filtering |

**Test fixtures:** `testdata/vulnerable-app/` contains intentionally vulnerable Python (`app.py`, `utils.py`) and Go (`server.go`) files. The integration tests verify that the full pipeline finds the expected vulnerability classes.

**Running tests:** `go test ./... -timeout 120s`

---

## Conventions

### Code style
- Standard Go formatting (`gofmt`)
- Package-level doc comments on every package
- Exported types and functions have doc comments
- Internal packages under `internal/` — not importable by external code

### Naming
- `NodeKind`, `EdgeKind` — string-typed enums with `Kind` prefix constants
- `VulnClass` — kebab-case string values (`sql-injection`, not `SQLInjection`)
- `Severity` — lowercase string values (`critical`, not `Critical`)
- Finding IDs — `HB-NNNN` format (zero-padded)
- NodeIDs — `"kind:file:name:index"` format

### Error handling
- Return `error` from functions that can fail
- Wrap errors with context: `fmt.Errorf("discovery: %w", err)`
- Skip unparseable files silently during scan (log, don't crash)
- Malformed code produces `HasErrors=true`, not an error return

### Adding a new language (checklist)
1. `internal/discovery/discovery.go` — add extensions to `extMap`
2. `internal/parser/parser.go` — add grammar func to `langToGrammarFunc`, filename to `langToFilename`
3. `internal/parser/parser.go` — add S-expression queries to `queryMap` (if the language has functions/calls/imports)
4. `internal/vulnquery/vulnquery.go` — add sink definitions to `sinkRegistry`
5. `internal/discovery/discovery.go` — add to `SupportedLanguages()` return
6. Tests for each of the above

### Adding a new vulnerability class (checklist)
1. `internal/vulnquery/vulnquery.go` — add `VulnClass` constant
2. Add sink definitions to `sinkRegistry` OR add a new `check*` method
3. Call the new check from `Run()` and `RunFocused()`
4. Add tests covering detection and false-positive avoidance
5. Update README.md vulnerability table

---

## Key Design Decisions & Rationale

### Why gotreesitter instead of smacker/go-tree-sitter?
smacker/go-tree-sitter wraps the C tree-sitter runtime via CGO. This means:
- Cross-compilation requires a C toolchain per target
- `go install` fails for users without gcc
- Windows builds need MinGW/MSYS2
- WASM targets are impossible

gotreesitter is a ground-up pure Go reimplementation. 206 grammars, full query engine, no CGO. The tradeoff is ~2.4x slower full parse vs C, but incremental parsing is 69x faster. For a CLI that parses once and analyzes, the full-parse overhead is acceptable.

### Why single-language call resolution in Phase 1?
Cross-language call resolution is heuristic (matching URL patterns, gRPC service names, etc.). Shipping heuristic edges without confidence scoring would produce confusing false positives. Phase 1 ships with correct single-language resolution. Phase 2 adds cross-language edges with explicit confidence scores.

### Why sink-based detection instead of taint tracking?
Full taint tracking requires control flow graphs (CFG) and program dependency graphs (PDG) in the CPG. Phase 1's CPG only has AST-level information (functions, calls, strings). Sink-based detection ("this function is dangerous") is sound with AST-level data. Taint tracking ("this specific input reaches this specific sink") requires Phase 2's CFG/PDG additions.

### Why SARIF as default output?
SARIF is the standard for static analysis results. GitHub, GitLab, Azure DevOps, and most CI systems can ingest SARIF natively. Shipping SARIF-first means Honey Badger integrates into existing workflows without custom parsers.

### Why cobra for CLI?
cobra is the de facto Go CLI framework (used by kubectl, hugo, gh). It provides subcommands, flag parsing, help generation, and shell completion out of the box. No reason to use anything else.

---

## File Map

```
honey-badger/
├── main.go                          Entry point
├── go.mod                           Module definition
├── go.sum                           Dependency checksums
├── README.md                        User-facing documentation
├── LICENSE                          MIT license
├── idea.md                          Original product vision document
├── plan.md                          Phased development roadmap
├── STEERING.md                      This file
├── .gitignore                       Go defaults
├── cmd/
│   ├── root.go                      Root command + global flags
│   ├── scan.go                      Scan pipeline
│   ├── understand.go                Codebase understanding
│   ├── info.go                      Language info
│   ├── version.go                   Version command
│   └── cmd_test.go                  CLI tests (15 tests)
├── internal/
│   ├── discovery/
│   │   ├── discovery.go             File walking + language detection
│   │   └── discovery_test.go        35 subtests
│   ├── parser/
│   │   ├── parser.go                Tree-sitter AST extraction
│   │   └── parser_test.go           16 tests
│   ├── cpg/
│   │   ├── cpg.go                   Code Property Graph
│   │   └── cpg_test.go              14 tests
│   ├── vulnquery/
│   │   ├── vulnquery.go             Vulnerability detection
│   │   └── vulnquery_test.go        17 tests
│   └── report/
│       ├── report.go                SARIF/JSON/Markdown output
│       └── report_test.go           10 tests
├── test/
│   └── integration_test.go          End-to-end tests (5 tests)
└── testdata/
    └── vulnerable-app/
        ├── app.py                   Vulnerable Python Flask app
        ├── utils.py                 Vulnerable Python utilities
        └── server.go                Vulnerable Go HTTP server
```

---

*Last updated: April 17, 2026*
