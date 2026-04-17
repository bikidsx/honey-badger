package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

var dbPassword = "admin123"

func handleQuery(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("postgres", "host=localhost")
	userID := r.URL.Query().Get("id")
	// SQL injection
	rows, _ := db.Query("SELECT * FROM users WHERE id = " + userID)
	defer rows.Close()
	fmt.Fprintf(w, "results: %v", rows)
}

func handleExec(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	// Command injection
	out, _ := exec.Command(cmd).Output()
	fmt.Fprintf(w, "%s", out)
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	// SSRF
	resp, _ := http.Get(url)
	defer resp.Body.Close()
	fmt.Fprintf(w, "proxied")
}

func main() {
	http.HandleFunc("/query", handleQuery)
	http.HandleFunc("/exec", handleExec)
	http.HandleFunc("/proxy", handleProxy)
	http.ListenAndServe(":8080", nil)
}
