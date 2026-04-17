package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bikidsx/honey-badger/internal/discovery"
)

func TestParsePython(t *testing.T) {
	src := []byte(`
import os
from pathlib import Path

def handle_request(user_input):
    query = "SELECT * FROM users WHERE id = " + user_input
    return os.popen(query).read()

class UserService:
    def get_user(self, uid):
        return uid
`)
	res, err := ParseSource("app.py", discovery.Python, src)
	if err != nil {
		t.Fatalf("ParseSource failed: %v", err)
	}
	if res.HasErrors {
		t.Error("expected no parse errors")
	}
	if len(res.Functions) < 2 {
		t.Errorf("expected at least 2 functions (handle_request, UserService), got %d", len(res.Functions))
	}
	if len(res.Calls) == 0 {
		t.Error("expected call expressions")
	}
	if len(res.Imports) == 0 {
		t.Error("expected imports")
	}
	if len(res.Strings) == 0 {
		t.Error("expected string literals")
	}

	// Verify function names
	funcNames := nodeNames(res.Functions)
	assertContains(t, funcNames, "handle_request")
	assertContains(t, funcNames, "UserService")
}

func TestParseJavaScript(t *testing.T) {
	src := []byte(`
import express from 'express';

function handleAuth(req, res) {
    const token = req.headers.authorization;
    fetch('/api/users?token=' + token);
    return res.json({ ok: true });
}

const helper = (x) => x + 1;
`)
	res, err := ParseSource("app.js", discovery.JavaScript, src)
	if err != nil {
		t.Fatalf("ParseSource failed: %v", err)
	}
	if res.HasErrors {
		t.Error("expected no parse errors")
	}
	if len(res.Functions) == 0 {
		t.Error("expected function declarations")
	}
	if len(res.Calls) == 0 {
		t.Error("expected call expressions")
	}
	if len(res.Imports) == 0 {
		t.Error("expected imports")
	}

	funcNames := nodeNames(res.Functions)
	assertContains(t, funcNames, "handleAuth")
}

func TestParseTypeScript(t *testing.T) {
	src := []byte(`
import { Request, Response } from 'express';

function processInput(input: string): string {
    return input.trim();
}

class ApiHandler {
    handle(req: Request): Response {
        return fetch(req.url);
    }
}
`)
	res, err := ParseSource("handler.ts", discovery.TypeScript, src)
	if err != nil {
		t.Fatalf("ParseSource failed: %v", err)
	}
	if len(res.Functions) == 0 {
		t.Error("expected function declarations")
	}
	funcNames := nodeNames(res.Functions)
	assertContains(t, funcNames, "processInput")
}

func TestParseGo(t *testing.T) {
	src := []byte(`package main

import (
	"fmt"
	"net/http"
)

func handleRequest(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("id")
	fmt.Fprintf(w, "Hello %s", input)
}

type Server struct{}

func (s *Server) Start() error {
	return http.ListenAndServe(":8080", nil)
}
`)
	res, err := ParseSource("main.go", discovery.Go, src)
	if err != nil {
		t.Fatalf("ParseSource failed: %v", err)
	}
	if res.HasErrors {
		t.Error("expected no parse errors")
	}
	if len(res.Functions) < 2 {
		t.Errorf("expected at least 2 functions, got %d", len(res.Functions))
	}
	if len(res.Imports) < 2 {
		t.Errorf("expected at least 2 imports, got %d", len(res.Imports))
	}
	if len(res.Calls) == 0 {
		t.Error("expected call expressions")
	}

	funcNames := nodeNames(res.Functions)
	assertContains(t, funcNames, "handleRequest")
	assertContains(t, funcNames, "Start")
}

func TestParseSQL(t *testing.T) {
	src := []byte(`
SELECT * FROM users WHERE id = 1;
INSERT INTO logs (message) VALUES ('test');
`)
	res, err := ParseSource("query.sql", discovery.SQL, src)
	if err != nil {
		t.Fatalf("ParseSource failed: %v", err)
	}
	// SQL parsing should succeed even if no functions are extracted
	if res.Language != discovery.SQL {
		t.Errorf("expected SQL language, got %s", res.Language)
	}
}

func TestParseYAML(t *testing.T) {
	src := []byte(`
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
data:
  password: cGFzc3dvcmQ=
`)
	res, err := ParseSource("config.yaml", discovery.YAML, src)
	if err != nil {
		t.Fatalf("ParseSource failed: %v", err)
	}
	if res.Language != discovery.YAML {
		t.Errorf("expected YAML language, got %s", res.Language)
	}
}

func TestParseJSON(t *testing.T) {
	src := []byte(`{
  "database": {
    "host": "localhost",
    "password": "secret123"
  }
}`)
	res, err := ParseSource("config.json", discovery.JSON, src)
	if err != nil {
		t.Fatalf("ParseSource failed: %v", err)
	}
	if res.Language != discovery.JSON {
		t.Errorf("expected JSON language, got %s", res.Language)
	}
}

func TestParseHCL(t *testing.T) {
	src := []byte(`
resource "aws_instance" "web" {
  ami           = "ami-12345"
  instance_type = "t2.micro"
}
`)
	res, err := ParseSource("main.tf", discovery.HCL, src)
	if err != nil {
		t.Fatalf("ParseSource failed: %v", err)
	}
	if res.Language != discovery.HCL {
		t.Errorf("expected HCL language, got %s", res.Language)
	}
}

func TestParseDockerfile(t *testing.T) {
	src := []byte(`FROM golang:1.22-alpine
RUN apk add --no-cache git
COPY . /app
WORKDIR /app
RUN go build -o server .
EXPOSE 8080
CMD ["./server"]
`)
	res, err := ParseSource("Dockerfile", discovery.Dockerfile, src)
	if err != nil {
		t.Fatalf("ParseSource failed: %v", err)
	}
	if res.Language != discovery.Dockerfile {
		t.Errorf("expected Dockerfile language, got %s", res.Language)
	}
}

func TestParseUnsupportedLanguage(t *testing.T) {
	_, err := ParseSource("test.xyz", discovery.Unknown, []byte("hello"))
	if err == nil {
		t.Fatal("expected error for unsupported language")
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.py")
	err := os.WriteFile(path, []byte("def hello(): pass"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	res, err := ParseFile(path, discovery.Python)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if len(res.Functions) == 0 {
		t.Error("expected at least one function")
	}
}

func TestParseFileNotFound(t *testing.T) {
	_, err := ParseFile("/nonexistent/file.py", discovery.Python)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParseNodePositions(t *testing.T) {
	src := []byte("def foo():\n    pass\n")
	res, err := ParseSource("test.py", discovery.Python, src)
	if err != nil {
		t.Fatalf("ParseSource failed: %v", err)
	}
	if len(res.Functions) == 0 {
		t.Fatal("expected at least one function")
	}
	fn := res.Functions[0]
	if fn.Name != "foo" {
		t.Errorf("expected function name 'foo', got %q", fn.Name)
	}
	if fn.StartRow < 0 || fn.StartCol < 0 {
		t.Errorf("invalid position: row=%d col=%d", fn.StartRow, fn.StartCol)
	}
}

func TestParseMalformedCode(t *testing.T) {
	// Malformed Python — should parse with errors but not crash
	src := []byte("def (broken syntax {{{")
	res, err := ParseSource("bad.py", discovery.Python, src)
	if err != nil {
		t.Fatalf("ParseSource should not error on malformed code: %v", err)
	}
	if !res.HasErrors {
		t.Error("expected HasErrors=true for malformed code")
	}
}

func TestParseEmptyFile(t *testing.T) {
	res, err := ParseSource("empty.py", discovery.Python, []byte(""))
	if err != nil {
		t.Fatalf("ParseSource failed on empty file: %v", err)
	}
	if res.HasErrors {
		t.Error("empty file should not have parse errors")
	}
	if len(res.Functions) != 0 {
		t.Error("empty file should have no functions")
	}
}

func TestSupportedForParsing(t *testing.T) {
	langs := SupportedForParsing()
	if len(langs) < 9 {
		t.Errorf("expected at least 9 supported languages, got %d", len(langs))
	}
}

// helpers

func nodeNames(nodes []Node) []string {
	names := make([]string, len(nodes))
	for i, n := range nodes {
		names[i] = n.Name
	}
	return names
}

func assertContains(t *testing.T, items []string, want string) {
	t.Helper()
	for _, item := range items {
		if item == want {
			return
		}
	}
	t.Errorf("expected %v to contain %q", items, want)
}
