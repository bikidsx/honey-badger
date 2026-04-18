// Package discovery walks a directory tree, detects programming languages,
// and returns a structured inventory of source files.
package discovery

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// Language represents a detected programming language.
type Language string

const (
	Python     Language = "python"
	JavaScript Language = "javascript"
	TypeScript Language = "typescript"
	Go         Language = "go"
	SQL        Language = "sql"
	YAML       Language = "yaml"
	JSON       Language = "json"
	HCL        Language = "hcl"
	Dockerfile Language = "dockerfile"
	Java       Language = "java"
	CSharp     Language = "csharp"
	Rust       Language = "rust"
	PHP        Language = "php"
	Unknown    Language = "unknown"
)

// SourceFile represents a discovered file with its detected language.
type SourceFile struct {
	Path     string   // relative path from scan root
	Language Language // detected language
	Size     int64    // file size in bytes
}

// Result holds the output of a discovery scan.
type Result struct {
	Root  string                // scan root directory
	Files []SourceFile          // all discovered source files
	Stats map[Language]int      // file count per language
}

// extMap maps file extensions to languages.
var extMap = map[string]Language{
	".py":    Python,
	".pyw":   Python,
	".js":    JavaScript,
	".mjs":   JavaScript,
	".cjs":   JavaScript,
	".jsx":   JavaScript,
	".ts":    TypeScript,
	".tsx":   TypeScript,
	".mts":   TypeScript,
	".cts":   TypeScript,
	".go":    Go,
	".sql":   SQL,
	".yaml":  YAML,
	".yml":   YAML,
	".json":  JSON,
	".tf":    HCL,
	".tfvars": HCL,
	".hcl":  HCL,
	".java":  Java,
	".cs":    CSharp,
	".rs":    Rust,
	".php":   PHP,
}

// defaultIgnoreDirs are directories skipped during discovery.
var defaultIgnoreDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
	"dist":         true,
	"build":        true,
	".next":        true,
	".cache":       true,
	"target":       true,
}

// DetectLanguage returns the language for a given file path.
func DetectLanguage(path string) Language {
	base := filepath.Base(path)

	// Dockerfile detection (Dockerfile, Dockerfile.prod, etc.)
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
		return Dockerfile
	}

	ext := strings.ToLower(filepath.Ext(path))
	if lang, ok := extMap[ext]; ok {
		return lang
	}
	return Unknown
}

// Options configures the discovery scan.
type Options struct {
	IgnoreDirs  map[string]bool // directories to skip (merged with defaults)
	FilterLangs []Language      // if non-empty, only include these languages
}

// Scan walks root and returns all recognized source files.
func Scan(root string, opts *Options) (*Result, error) {
	ignoreDirs := make(map[string]bool)
	for k, v := range defaultIgnoreDirs {
		ignoreDirs[k] = v
	}
	if opts != nil {
		for k, v := range opts.IgnoreDirs {
			ignoreDirs[k] = v
		}
	}

	var filterSet map[Language]bool
	if opts != nil && len(opts.FilterLangs) > 0 {
		filterSet = make(map[Language]bool, len(opts.FilterLangs))
		for _, l := range opts.FilterLangs {
			filterSet[l] = true
		}
	}

	res := &Result{
		Root:  root,
		Stats: make(map[Language]int),
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if ignoreDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		lang := DetectLanguage(path)
		if lang == Unknown {
			return nil
		}
		if filterSet != nil && !filterSet[lang] {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil // skip files we can't stat
		}

		rel, _ := filepath.Rel(root, path)
		res.Files = append(res.Files, SourceFile{
			Path:     filepath.ToSlash(rel),
			Language: lang,
			Size:     info.Size(),
		})
		res.Stats[lang]++
		return nil
	})

	return res, err
}

// SupportedLanguages returns all languages Honey Badger can detect.
func SupportedLanguages() []Language {
	return []Language{
		Python, JavaScript, TypeScript, Go, Java, CSharp, Rust, PHP, SQL, YAML, JSON, HCL, Dockerfile,
	}
}
