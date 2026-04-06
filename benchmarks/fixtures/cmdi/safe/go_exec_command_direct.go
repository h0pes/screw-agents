// Fixture: Safe exec.Command with separate args — Go
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-78
// Agent: cmdi
// Pattern: exec.Command with explicit argument separation, no shell, input validation

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	ipRegex       = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	filenameRegex = regexp.MustCompile(`^[\w\-]+\.[a-z]{1,5}$`)
)

// SAFE: exec.Command with separate arguments — no shell involved
// Each argument is passed directly to ping as argv, not interpreted by sh
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	// Validate IP address format
	if !ipRegex.MatchString(host) {
		http.Error(w, `{"error":"invalid IP address"}`, http.StatusBadRequest)
		return
	}
	// Double-check with net.ParseIP
	if net.ParseIP(host) == nil {
		http.Error(w, `{"error":"invalid IP address"}`, http.StatusBadRequest)
		return
	}

	// SAFE: no shell, arguments are separate strings
	out, err := exec.Command("ping", "-c", "3", "-W", "5", host).CombinedOutput()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"reachable": err == nil,
		"output":    string(out),
	})
}

// SAFE: exec.Command with validated filename and -- separator
func checksumHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if !filenameRegex.MatchString(filename) {
		http.Error(w, `{"error":"invalid filename"}`, http.StatusBadRequest)
		return
	}

	uploadDir := "/var/app/uploads"
	fullPath := filepath.Join(uploadDir, filename)

	// Path traversal check
	if !strings.HasPrefix(fullPath, uploadDir+"/") {
		http.Error(w, `{"error":"path traversal"}`, http.StatusBadRequest)
		return
	}

	// SAFE: exec.Command with separate args; -- prevents option injection
	out, err := exec.Command("sha256sum", "--", fullPath).Output()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "checksum failed"})
		return
	}
	parts := strings.Fields(string(out))
	json.NewEncoder(w).Encode(map[string]string{"checksum": parts[0]})
}

// SAFE: exec.Command with allowlisted command selection
func toolHandler(w http.ResponseWriter, r *http.Request) {
	tool := r.URL.Query().Get("tool")
	target := r.URL.Query().Get("target")

	allowedTools := map[string]string{
		"df":     "df",
		"uptime": "uptime",
		"whoami": "whoami",
	}

	binary, ok := allowedTools[tool]
	if !ok {
		http.Error(w, `{"error":"unknown tool"}`, http.StatusBadRequest)
		return
	}

	// SAFE: binary is from server-controlled allowlist; no user args for these commands
	out, _ := exec.Command(binary).Output()
	w.Header().Set("Content-Type", "application/json")
	_ = target // not used in command — just for API compatibility
	json.NewEncoder(w).Encode(map[string]string{"output": string(out)})
}

func main() {
	http.HandleFunc("/api/ping", pingHandler)
	http.HandleFunc("/api/checksum", checksumHandler)
	http.HandleFunc("/api/tool", toolHandler)
	http.ListenAndServe(":8080", nil)
}
