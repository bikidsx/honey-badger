# Honey Badger — Development Plan

> Living roadmap. Updated as phases complete.
>
> **Status as of April 2026:** Phase 1 complete. Phase 1.5 in progress.

---

## Phase 1 — Foundation ✅ COMPLETE

**Goal:** Working CLI that parses a polyglot repo, builds a CPG, finds common vulns, outputs SARIF.

### What was built

| Component | Status | Details |
|---|---|---|
| Go module + CLI skeleton | ✅ | cobra v1.9.1, `hb scan`, `hb understand`, `hb info`, `hb version` |
| File discovery engine | ✅ | 13 languages detected, default ignore dirs, language filtering |
| Tree-sitter parser | ✅ | gotreesitter v0.14.0 (pure Go, no CGO), extracts functions/calls/imports/strings |
| Code Property Graph | ✅ | 5 node kinds, 4 edge kinds, cross-file call resolution (single-language) |
| Vulnerability query engine | ✅ | 7 vuln classes, sink registry for Python/JS/Go/Java/C#/Rust/PHP, 8 secret regex patterns |
| Report engine | ✅ | SARIF v2.1.0, JSON, Markdown, HTML (auto-opens in browser) |
| Integration tests | ✅ | Vulnerable Python+Go test app, 23 vulns found across 6 classes |
| README | ✅ | Installation, usage, architecture, CI/CD integration |

**Test count:** 111 tests across 7 packages, all passing.

**Dependencies:** cobra v1.9.1, gotreesitter v0.14.0. No CGO. Single binary.

### What Phase 1 does NOT have (deferred intentionally)

- No cross-language CPG edges (Python call → Go function)
- No LLM integration
- No taint tracking beyond call resolution
- No `hb trace` or `hb query` commands
- No dependency analysis (SCA) — but Trivy integration now available

---

## Phase 1.5 — Polish & Ship (Weeks 1–2)

**Goal:** Make Phase 1 production-ready for open source launch.

### Tasks

| Task | Priority | Status |
|---|---|---|
| GitHub Actions CI (test on push, build matrix: linux/mac/windows) | P0 | ✅ `.github/workflows/ci.yml` |
| Goreleaser config for cross-platform binaries | P0 | ✅ `.goreleaser.yml` + release workflow |
| Fix binary name (`hb` not `honey-badger`) | P0 | ✅ `cmd/hb/main.go` entrypoint |
| Wire Java + C# + Rust + PHP parsers | P1 | ✅ 4 languages, full query patterns + sinks |
| Add `--exclude` flag to scan (skip specific dirs/files) | P1 | ✅ Merged with discovery.Options.IgnoreDirs |
| Parallel file parsing with goroutines + worker pool | P1 | ✅ GOMAXPROCS workers via channels |
| Laravel/Symfony framework sinks | P1 | ✅ raw queries, Doctrine, deserialization |
| External tool integration (Trivy + Semgrep) | P1 | ✅ `internal/integrations/` package |
| idea.md vision document | P1 | ✅ Saved to repo root |
| Benchmark suite (parse time, CPG build time per repo size) | P2 | To do |
| `hb scan --sarif-file=results.sarif` (write to file instead of stdout) | P2 | To do |
| Progress bar / spinner for large repos | P2 | To do |
| Add `.hbignore` file support | P2 | To do |

### Exit criteria

- `go install github.com/bikidsx/honey-badger/cmd/hb@latest` works
- CI green on all 3 platforms
- Release v0.1.0 tagged

---

## Phase 2 — Cross-Language Intelligence (Months 1–3 from here)

**Goal:** Trace data flow across language boundaries. This is the killer feature.

### 2A — Cross-Language CPG Edges

The hardest and most valuable piece. A user input entering at `handler.ts:42` should be traceable through a Python API to a Go service to a SQL sink.

| Task | Details |
|---|---|
| Define cross-language edge types | `EdgeRESTCall`, `EdgeGRPCCall`, `EdgeDBQuery`, `EdgeEnvVar`, `EdgeFileIO` |
| REST boundary detection | Match HTTP client calls (fetch, requests.get, http.Get) to route handlers (@app.route, http.HandleFunc) by URL pattern |
| Import-based cross-language linking | Python `import` → Go package, JS `require` → native module |
| Shared database detection | SQL table names referenced across languages → implicit data flow edge |
| Environment variable tracking | `os.environ["KEY"]` in Python ↔ `os.Getenv("KEY")` in Go |

**Key design constraint:** Cross-language edges are heuristic, not proven. They must be labeled with a confidence score. The CPGEdge struct needs a `Confidence float64` field.

### 2B — Taint Tracking Engine

| Task | Details |
|---|---|
| Define source/sink/sanitizer model | Sources: request params, env vars, file reads. Sinks: SQL, exec, HTTP. Sanitizers: escape functions, validators. |
| Intra-function taint propagation | Track which variables carry tainted data within a function body |
| Inter-function taint propagation | Follow taint through call edges in the CPG |
| Cross-file taint propagation | Follow taint through resolved call edges across files |
| Taint path reporting | Report the full chain: source → intermediate → ... → sink with file:line at each step |

**Implementation approach:** BFS/DFS over CPG edges starting from source nodes, tracking taint state. The `FindReachable` method in cpg.go is the seed — extend it with taint state tracking.

### 2C — `hb trace` Command

```bash
hb trace ./my-app --from="api/handler.ts:parseBody" --to="db/query.go:Execute"
```

Answers: "Can data flow from A to B?" Returns the path if yes, or "no path found."

### 2D — `hb query` Command

```bash
hb query ./my-app "can untrusted user input reach the database?"
```

This requires LLM integration. Two approaches:

1. **Local-first (preferred):** Translate natural language to a CPG graph query using an LLM, then execute the query deterministically against the CPG. The LLM never sees the code — it only generates the query.
2. **RAG approach:** Chunk the CPG into semantically meaningful units, embed them, retrieve relevant chunks for the question, feed to LLM for reasoning.

Start with approach 1. It's more deterministic and doesn't require embedding infrastructure.

### 2E — Dependency Behavioral Mapping

| Task | Details |
|---|---|
| Parse package manifests | `package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, `pom.xml` |
| Build behavioral index for top 50 packages per ecosystem | What does `requests.get()` do with untrusted URLs? Does `express.json()` sanitize? |
| Map dependency calls to behavioral properties | `follows_redirects`, `sends_cookies`, `deserializes_input`, `executes_code` |
| Integrate with taint tracking | A call to `requests.get(user_url)` is SSRF even if requests has no CVE |

### Phase 2 exit criteria

- `hb trace` works across 2+ languages
- `hb query` answers basic taint questions
- Cross-language CPG edges for REST boundaries
- Dependency behavioral mapping for top 20 npm + pip packages

---

## Phase 3 — Agent Reasoning (Months 4–6 from here)

**Goal:** Multi-agent architecture that reasons about vulnerabilities like a human pentester.

### 3A — Understand Agent

Reads the CPG and produces a structured understanding:
- Entry points (public API routes, CLI handlers, message consumers)
- Trust boundaries (auth middleware, input validation layers)
- Data stores (databases, caches, file systems)
- Third-party integrations (external APIs, payment processors)
- Authentication/authorization model

Output: A structured JSON "codebase map" that other agents consume.

### 3B — Attack Planner Agent

Given the codebase map, generates attack hypotheses:
- "If I can bypass auth on endpoint X, I can reach admin function Y"
- "User input at A flows through B (no sanitization) to SQL sink at C"
- "Rate limiting is only on /login, not on /api/reset-password"

Uses Chain-of-Thought prompting. Each hypothesis is a structured plan with steps.

### 3C — Validator Agent

Takes each attack hypothesis and attempts to confirm or refute it:
- Static PoC generation (code that would exploit the vuln)
- Checks for sanitizers/validators in the taint path
- Checks for framework-level protections (CSRF tokens, CSP headers)
- Assigns confidence score

### 3D — Business Logic Vulnerability Detection

The hardest class of vulns. Requires understanding *intent*, not just data flow:
- "This endpoint should be admin-only but has no auth check"
- "This payment flow can be replayed"
- "This rate limiter can be bypassed by changing the user-agent"

Approach: Compare the codebase map (what the code does) against common security patterns (what it should do). Use LLM to identify gaps.

### 3E — PoC Generation

For confirmed vulnerabilities, generate:
- Curl commands that demonstrate the exploit
- Python scripts that reproduce the attack
- Step-by-step reproduction instructions

**Safety constraint:** PoCs are generated but never executed. They are informational only.

### Phase 3 exit criteria

- Multi-agent pipeline runs end-to-end
- Business logic vulns detected on test apps
- PoC generation for at least injection and auth bypass classes
- False positive rate < 30% on benchmark repos

---

## Phase 4 — Scale & Ecosystem (Months 7–9 from here)

**Goal:** Make Honey Badger extensible and embeddable.

### 4A — Plugin System

```go
// Custom vulnerability detector
type VulnPlugin interface {
    Name() string
    Check(graph *cpg.Graph) []vulnquery.Finding
}
```

Users can write Go plugins that receive the CPG and return findings. Load via `--plugin=./my-checker.so` or a plugin directory.

### 4B — MCP Server

Expose Honey Badger as an MCP (Model Context Protocol) server so other AI tools can query it:

```
Tool: hb_scan — scan a codebase
Tool: hb_query — ask a security question about a codebase
Tool: hb_trace — trace data flow between two points
Tool: hb_understand — get codebase structure
```

This makes Honey Badger composable with any AI agent framework.

### 4C — IDE Integration (LSP)

Run `hb` as a Language Server Protocol server:
- Real-time vulnerability highlighting as you type
- Inline taint flow visualization
- "Show me where this input goes" code lens
- Quick-fix suggestions

### 4D — Community Vulnerability Patterns

A `.hb/patterns/` directory where users can define custom detection rules in a YAML DSL:

```yaml
- id: custom-auth-bypass
  description: "Missing auth check on admin endpoint"
  pattern:
    match: call_to("handleAdmin")
    without: call_to("requireAuth") in_ancestors
  severity: critical
```

### 4E — Additional Languages

Wire remaining gotreesitter grammars (206 available):
- ~~Phase 4a: Rust, C, C++, Java, C#, PHP, Ruby~~ (Java, C#, Rust, PHP done in Phase 1.5)
- Phase 4a: C, C++, Ruby
- Phase 4b: Kotlin, Swift, Scala, Elixir, Dart
- Phase 4c: Community-contributed grammars

### Phase 4 exit criteria

- Plugin system with at least 3 community plugins
- MCP server passing conformance tests
- LSP server with basic diagnostics in VS Code
- 20+ languages with full vuln detection

---

## Milestones & Releases

| Version | Phase | Key feature |
|---|---|---|
| v0.1.0 | 1.5 | First public release. 13 languages, 7 vuln classes, Trivy+Semgrep integration, SARIF output. |
| v0.2.0 | 2A | Cross-language CPG edges (REST boundaries) |
| v0.3.0 | 2B–C | Taint tracking + `hb trace` command |
| v0.4.0 | 2D | `hb query` with LLM integration |
| v0.5.0 | 2E | Dependency behavioral mapping |
| v0.6.0 | 3A–B | Understand + Attack agents |
| v0.7.0 | 3C–D | Validator agent + business logic detection |
| v0.8.0 | 3E | PoC generation |
| v0.9.0 | 4A–B | Plugin system + MCP server |
| v1.0.0 | 4C–E | LSP, community patterns, 20+ languages |

---

## Technical Debt & Known Gaps

| Item | Severity | When to fix |
|---|---|---|
| CPG edge lookup is O(n) linear scan | Low (fine for <100k edges) | Phase 2 if perf becomes an issue — add adjacency list index |
| No CFG (control flow graph) in CPG | Medium | Phase 2B — needed for intra-function taint tracking |
| No PDG (program dependency graph) in CPG | Medium | Phase 2B — needed for data flow analysis |
| Parser queries are language-specific hardcoded strings | Low | Phase 4D — move to external query files |
| Sink registry is hardcoded in Go | Low | Phase 4A — make it plugin/config-driven |
| No caching of parse results | Low | Phase 1.5 — add content-hash based cache |
| `os.Exit(1)` in scan command for CI mode | Low | Phase 1.5 — return error instead, let main handle exit |
| Secret patterns are regex-only | Medium | Phase 2 — add entropy-based detection |

---

*Last updated: April 18, 2026*
