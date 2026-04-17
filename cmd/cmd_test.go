package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func executeCommand(args ...string) (string, error) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return buf.String(), err
}

func TestRootCommand(t *testing.T) {
	_, err := executeCommand()
	if err != nil {
		t.Fatalf("root command failed: %v", err)
	}
}

func TestVersionCommand(t *testing.T) {
	out, err := executeCommand("version")
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	if !strings.Contains(out, "hb version") {
		t.Fatalf("expected version output, got: %q", out)
	}
}

func TestScanRequiresPath(t *testing.T) {
	_, err := executeCommand("scan")
	if err == nil {
		t.Fatal("scan should fail without a path argument")
	}
}

func TestScanWithPath(t *testing.T) {
	out, err := executeCommand("scan", ".")
	if err != nil {
		t.Fatalf("scan with path failed: %v", err)
	}
	if !strings.Contains(out, "scanning: .") {
		t.Fatalf("expected scanning output, got: %q", out)
	}
	if !strings.Contains(out, "Found") {
		t.Fatalf("expected discovery output, got: %q", out)
	}
}

func TestUnderstandRequiresPath(t *testing.T) {
	_, err := executeCommand("understand")
	if err == nil {
		t.Fatal("understand should fail without a path argument")
	}
}

func TestUnderstandWithPath(t *testing.T) {
	out, err := executeCommand("understand", ".")
	if err != nil {
		t.Fatalf("understand with path failed: %v", err)
	}
	if !strings.Contains(out, "understanding: .") {
		t.Fatalf("expected understanding output, got: %q", out)
	}
	if !strings.Contains(out, "Functions:") {
		t.Fatalf("expected stats output, got: %q", out)
	}
}

func TestInfoRequiresPath(t *testing.T) {
	_, err := executeCommand("info")
	if err == nil {
		t.Fatal("info should fail without a path argument")
	}
}

func TestInfoWithPath(t *testing.T) {
	out, err := executeCommand("info", ".")
	if err != nil {
		t.Fatalf("info with path failed: %v", err)
	}
	if !strings.Contains(out, "info: .") {
		t.Fatalf("expected info output, got: %q", out)
	}
	if !strings.Contains(out, "Total files:") {
		t.Fatalf("expected file count, got: %q", out)
	}
}

func TestScanProducesSARIF(t *testing.T) {
	out, err := executeCommand("scan", ".", "-o", "sarif")
	if err != nil {
		t.Fatalf("scan with SARIF output failed: %v", err)
	}
	if !strings.Contains(out, "2.1.0") {
		t.Error("expected SARIF version in output")
	}
}

func TestScanProducesJSON(t *testing.T) {
	out, err := executeCommand("scan", ".", "-o", "json")
	if err != nil {
		t.Fatalf("scan with JSON output failed: %v", err)
	}
	// JSON output should be valid (either null or array)
	trimmed := strings.TrimSpace(out)
	// The output includes the progress lines + JSON
	if !strings.Contains(trimmed, "scanning:") {
		t.Error("expected scanning progress in output")
	}
}

func TestScanProducesMarkdown(t *testing.T) {
	out, err := executeCommand("scan", ".", "-o", "markdown")
	if err != nil {
		t.Fatalf("scan with markdown output failed: %v", err)
	}
	if !strings.Contains(out, "Honey Badger") {
		t.Error("expected Honey Badger in markdown output")
	}
}

func TestUnderstandCallgraph(t *testing.T) {
	out, err := executeCommand("understand", ".", "--show=callgraph")
	if err != nil {
		t.Fatalf("understand with --show=callgraph failed: %v", err)
	}
	if !strings.Contains(out, "Call Graph") {
		t.Error("expected Call Graph header")
	}
}

func TestUnderstandEntrypoints(t *testing.T) {
	out, err := executeCommand("understand", ".", "--show=entrypoints")
	if err != nil {
		t.Fatalf("understand with --show=entrypoints failed: %v", err)
	}
	if !strings.Contains(out, "Entry Points") {
		t.Error("expected Entry Points header")
	}
}
