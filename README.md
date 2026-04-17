<p align="center">
  <img src="data/image.png" alt="Honey Badger" width="400">
</p>

<h1 align="center">🦡 Honey Badger</h1>

<p align="center"><strong>Honey Badger don't care about your defenses.</strong></p>

A repository-level, language-agnostic, semantics-first codebase security analysis CLI. Honey Badger ingests an entire codebase — all languages, all configs — builds a unified Code Property Graph, and finds vulnerabilities that span files and functions.

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Why Honey Badger?

Current security tools treat code like a pile of text — scanning file-by-file, one language at a time. The most dangerous vulnerabilities (cross-file taint flows, business logic flaws, multi-step attack chains) are invisible to them.

Honey Badger builds a **Code Property Graph** from your entire repository and reasons about it structurally:

- **Cross-file analysis** — traces data flow across function boundaries
- **Multi-language** — Python, JavaScript, TypeScript, Go, SQL, YAML, JSON, HCL, Dockerfiles
- **Tree-sitter powered** — real AST parsing via [gotreesitter](https://github.com/odvcencio/gotreesitter) (pure Go, no CGO)
- **Single binary** — no runtime dependencies, runs anywhere Go compiles
- **CI/CD native** — SARIF output, exit codes for pipeline gating

## Quick Start

```bash
# Install
go install github.com/bikidsx/honey-badger@latest

# Scan a codebase
hb scan ./my-app

# Understand the codebase (no attack, just map)
hb understand ./my-app

# Show detected languages
hb info ./my-app
```

## Usage

### Scan for vulnerabilities

```bash
# Full scan with SARIF output (default)
hb scan ./my-app

# JSON output
hb scan ./my-app -o json

# Markdown report
hb scan ./my-app -o markdown

# Focus on specific vulnerability classes
hb scan ./my-app --focus=sql-injection,command-injection

# Scan only specific languages
hb scan ./my-app --langs=python,go

# CI/CD mode — exit 1 if critical vulns found
hb scan ./my-app --ci --fail-on=critical
```

### Understand a codebase

```bash
# Codebase statistics
hb understand ./my-app

# Show the call graph
hb understand ./my-app --show=callgraph

# Show entry points (functions with no callers)
hb understand ./my-app --show=entrypoints
```

### Get repository info

```bash
hb info ./my-app
```

## What It Finds

| Vulnerability Class | Description | Severity |
|---|---|---|
| SQL Injection | Database queries built with string concatenation | High |
| Command Injection | OS command execution with unsanitized input | Critical |
| SSRF | HTTP requests with user-controlled URLs | High |
| XSS | DOM manipulation with unsanitized input | High |
| Path Traversal | File operations with user-controlled paths | Medium |
| Hardcoded Secrets | Passwords, API keys, AWS credentials, tokens in source | Critical/High |

### Secret Detection Patterns

- Hardcoded passwords, API keys, tokens
- AWS Access Key IDs (`AKIA...`)
- GitHub personal access tokens (`ghp_...`)
- Private keys (`-----BEGIN PRIVATE KEY-----`)
- Connection strings

## Architecture

```
hb scan ./my-app
    │
    ├── Discovery ─────── Walk directory, detect languages, filter files
    │
    ├── Parser ────────── Tree-sitter AST parsing (functions, calls, imports, strings)
    │
    ├── CPG Builder ───── Code Property Graph with cross-file call resolution
    │
    ├── Vuln Query ────── Sink/source matching, secret detection, SQL concat detection
    │
    └── Report ────────── SARIF v2.1.0, JSON, or Markdown output
```

### Packages

| Package | Purpose |
|---|---|
| `cmd/` | CLI commands (scan, understand, info, version) |
| `internal/discovery/` | File discovery and language detection |
| `internal/parser/` | Tree-sitter AST parsing |
| `internal/cpg/` | Code Property Graph data structures and builder |
| `internal/vulnquery/` | Vulnerability detection engine |
| `internal/report/` | SARIF, JSON, and Markdown report generation |

## Supported Languages

| Language | Parsing | Vuln Detection |
|---|---|---|
| Python | ✅ Functions, calls, imports, strings | ✅ All 6 classes |
| JavaScript | ✅ Functions, calls, imports, strings | ✅ All 6 classes |
| TypeScript | ✅ Functions, calls, imports, strings | ✅ All 6 classes |
| Go | ✅ Functions, calls, imports, strings | ✅ All 6 classes |
| SQL | ✅ Parse tree | — |
| YAML | ✅ Parse tree | — |
| JSON | ✅ Parse tree | — |
| HCL (Terraform) | ✅ Parse tree | — |
| Dockerfile | ✅ Parse tree | — |

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    go install github.com/bikidsx/honey-badger@latest
    hb scan . --ci --fail-on=high -o sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Development

```bash
# Clone
git clone https://github.com/bikidsx/honey-badger.git
cd honey-badger

# Run tests
go test ./...

# Build
go build -o hb .

# Build with version
go build -ldflags "-X github.com/bikidsx/honey-badger/cmd.Version=v0.1.0" -o hb .
```

### Test Coverage

111 tests across 7 packages:
- CLI command tests (15 tests)
- Discovery engine tests (35 subtests)
- Tree-sitter parser tests (16 tests)
- CPG builder tests (14 tests)
- Vulnerability query engine tests (17 tests)
- Report engine tests (10 tests)
- Integration tests (5 tests)

## Roadmap

This is Phase 1. See [idea.md](idea.md) for the full vision.

- **Phase 2** — Cross-language taint tracking, RAG over vectorized CPG, dependency behavioral mapping
- **Phase 3** — Multi-agent reasoning (Understand → Attack → Validate), PoC generation
- **Phase 4** — Plugin system, MCP server, IDE integration, community vulnerability patterns

## Contributing

Contributions welcome. Please:

1. Fork the repo
2. Create a feature branch
3. Write tests for new functionality
4. Ensure `go test ./...` passes
5. Submit a PR

## License

[MIT](LICENSE)

---

*Honey Badger don't care. Honey Badger tears through your defenses.*
