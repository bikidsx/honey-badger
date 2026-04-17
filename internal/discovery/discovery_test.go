package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		path string
		want Language
	}{
		{"app.py", Python},
		{"script.pyw", Python},
		{"index.js", JavaScript},
		{"module.mjs", JavaScript},
		{"common.cjs", JavaScript},
		{"App.jsx", JavaScript},
		{"index.ts", TypeScript},
		{"App.tsx", TypeScript},
		{"main.go", Go},
		{"query.sql", SQL},
		{"config.yaml", YAML},
		{"config.yml", YAML},
		{"package.json", JSON},
		{"main.tf", HCL},
		{"vars.tfvars", HCL},
		{"config.hcl", HCL},
		{"Dockerfile", Dockerfile},
		{"Dockerfile.prod", Dockerfile},
		{"Dockerfile.dev", Dockerfile},
		{"README.md", Unknown},
		{"Makefile", Unknown},
		{"image.png", Unknown},
		{".gitignore", Unknown},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := DetectLanguage(tt.path)
			if got != tt.want {
				t.Errorf("DetectLanguage(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestDetectLanguageCaseInsensitive(t *testing.T) {
	// Extensions should be case-insensitive
	got := DetectLanguage("FILE.PY")
	if got != Python {
		t.Errorf("DetectLanguage(FILE.PY) = %q, want %q", got, Python)
	}
}

func TestDetectLanguageNestedPath(t *testing.T) {
	got := DetectLanguage("src/handlers/auth.ts")
	if got != TypeScript {
		t.Errorf("DetectLanguage(src/handlers/auth.ts) = %q, want %q", got, TypeScript)
	}
}

// setupTestDir creates a temporary directory tree for testing.
func setupTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// Create a realistic project structure
	files := map[string]string{
		"main.go":                     "package main",
		"go.mod":                      "module test",
		"cmd/root.go":                 "package cmd",
		"internal/handler.py":         "def handle(): pass",
		"web/index.ts":                "export default {}",
		"web/App.tsx":                 "export function App() {}",
		"web/utils.js":                "module.exports = {}",
		"db/schema.sql":               "CREATE TABLE t (id INT);",
		"config.yaml":                 "key: value",
		"deploy/main.tf":              "resource {}",
		"Dockerfile":                  "FROM golang:1.22",
		"Dockerfile.prod":             "FROM golang:1.22",
		"data.json":                   "{}",
		"README.md":                   "# Test",
		"node_modules/pkg/index.js":   "// should be ignored",
		".git/config":                 "// should be ignored",
		"vendor/lib/lib.go":           "// should be ignored",
		"__pycache__/cache.pyc":       "// should be ignored",
	}

	for relPath, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(relPath))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestScanFindsAllFiles(t *testing.T) {
	dir := setupTestDir(t)
	res, err := Scan(dir, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should find: main.go, cmd/root.go, handler.py, index.ts, App.tsx, utils.js,
	// schema.sql, config.yaml, main.tf, Dockerfile, Dockerfile.prod, data.json = 12 files
	if len(res.Files) != 12 {
		t.Errorf("expected 12 files, got %d", len(res.Files))
		for _, f := range res.Files {
			t.Logf("  %s (%s)", f.Path, f.Language)
		}
	}
}

func TestScanIgnoresDefaultDirs(t *testing.T) {
	dir := setupTestDir(t)
	res, err := Scan(dir, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	for _, f := range res.Files {
		for ignored := range defaultIgnoreDirs {
			if filepath.HasPrefix(f.Path, ignored) {
				t.Errorf("file %s should have been ignored (in %s)", f.Path, ignored)
			}
		}
	}
}

func TestScanStats(t *testing.T) {
	dir := setupTestDir(t)
	res, err := Scan(dir, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	expected := map[Language]int{
		Go:         2, // main.go, cmd/root.go
		Python:     1, // handler.py
		TypeScript: 2, // index.ts, App.tsx
		JavaScript: 1, // utils.js
		SQL:        1, // schema.sql
		YAML:       1, // config.yaml
		HCL:        1, // main.tf
		Dockerfile: 2, // Dockerfile, Dockerfile.prod
		JSON:       1, // data.json
	}

	for lang, want := range expected {
		got := res.Stats[lang]
		if got != want {
			t.Errorf("Stats[%s] = %d, want %d", lang, got, want)
		}
	}
}

func TestScanFilterLanguages(t *testing.T) {
	dir := setupTestDir(t)
	res, err := Scan(dir, &Options{
		FilterLangs: []Language{Go, Python},
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	for _, f := range res.Files {
		if f.Language != Go && f.Language != Python {
			t.Errorf("unexpected language %s for file %s", f.Language, f.Path)
		}
	}

	if len(res.Files) != 3 { // 2 Go + 1 Python
		t.Errorf("expected 3 files, got %d", len(res.Files))
	}
}

func TestScanCustomIgnoreDirs(t *testing.T) {
	dir := setupTestDir(t)
	res, err := Scan(dir, &Options{
		IgnoreDirs: map[string]bool{"deploy": true},
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	for _, f := range res.Files {
		if f.Language == HCL {
			t.Errorf("HCL file %s should have been ignored (deploy dir)", f.Path)
		}
	}
}

func TestScanNonexistentDir(t *testing.T) {
	_, err := Scan("/nonexistent/path/that/does/not/exist", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestScanEmptyDir(t *testing.T) {
	dir := t.TempDir()
	res, err := Scan(dir, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(res.Files) != 0 {
		t.Errorf("expected 0 files, got %d", len(res.Files))
	}
}

func TestScanRelativePaths(t *testing.T) {
	dir := setupTestDir(t)
	res, err := Scan(dir, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	for _, f := range res.Files {
		if filepath.IsAbs(f.Path) {
			t.Errorf("expected relative path, got absolute: %s", f.Path)
		}
	}
}

func TestScanFileSizes(t *testing.T) {
	dir := setupTestDir(t)
	res, err := Scan(dir, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	for _, f := range res.Files {
		if f.Size <= 0 {
			t.Errorf("file %s has invalid size: %d", f.Path, f.Size)
		}
	}
}

func TestSupportedLanguages(t *testing.T) {
	langs := SupportedLanguages()
	if len(langs) != 9 {
		t.Errorf("expected 9 supported languages, got %d", len(langs))
	}
}
