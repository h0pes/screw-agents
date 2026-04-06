// Fixture: Safe exec.Command with allowlist-validated input — Go
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-78
// Agent: cmdi
// Pattern: exec.Command with strict allowlist validation and -- separator

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

var filenameRegex = regexp.MustCompile(`^[\w\-]+\.[a-z]{1,5}$`)

// Strict allowlist of DNS record types
var allowedRecordTypes = map[string]bool{
	"A":     true,
	"AAAA":  true,
	"MX":    true,
	"TXT":   true,
	"CNAME": true,
	"NS":    true,
	"SOA":   true,
}

// Strict allowlist of domain suffixes for internal use
var allowedDomainSuffixes = []string{
	".example.com",
	".internal.corp",
}

// SAFE: exec.Command with allowlisted record type and validated domain
func dnsLookupHandler(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	recordType := r.URL.Query().Get("type")

	// Validate record type against allowlist
	if !allowedRecordTypes[strings.ToUpper(recordType)] {
		http.Error(w, `{"error":"unsupported record type"}`, http.StatusBadRequest)
		return
	}

	// Validate domain: must be a well-formed hostname with allowed suffix
	if !isValidDomain(domain) {
		http.Error(w, `{"error":"invalid or disallowed domain"}`, http.StatusBadRequest)
		return
	}

	// SAFE: exec.Command with separate args — no shell, validated inputs
	out, err := exec.Command("dig", "+short", strings.ToUpper(recordType), domain).Output()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain":  domain,
		"type":    recordType,
		"records": strings.Split(strings.TrimSpace(string(out)), "\n"),
		"error":   errStr(err),
	})
}

// SAFE: exec.Command("tar") with validated filenames, -- separator, no shell
func archiveHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Files []string `json:"files"`
		Name  string   `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	// Validate archive name
	if !filenameRegex.MatchString(req.Name) {
		http.Error(w, `{"error":"invalid archive name"}`, http.StatusBadRequest)
		return
	}

	uploadDir := "/var/app/uploads"

	// Validate every filename in the list
	for _, f := range req.Files {
		if !filenameRegex.MatchString(f) {
			http.Error(w, `{"error":"invalid filename in list"}`, http.StatusBadRequest)
			return
		}
		fullPath := filepath.Join(uploadDir, f)
		if !strings.HasPrefix(fullPath, uploadDir+"/") {
			http.Error(w, `{"error":"path traversal"}`, http.StatusBadRequest)
			return
		}
	}

	// Build args: tar -czf /path/archive.tar.gz -C /uploads -- file1 file2 ...
	args := []string{"-czf", filepath.Join("/tmp", req.Name), "-C", uploadDir, "--"}
	args = append(args, req.Files...)

	// SAFE: no shell, separate args, validated inputs, -- prevents option injection
	out, err := exec.Command("tar", args...).CombinedOutput()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": errStr(err) == "",
		"output": string(out),
	})
}

// SAFE: exec.Command with allowlisted binary and no user-controlled arguments
func systemInfoHandler(w http.ResponseWriter, r *http.Request) {
	metric := r.URL.Query().Get("metric")

	type cmdSpec struct {
		bin  string
		args []string
	}
	allowedMetrics := map[string]cmdSpec{
		"disk":    {bin: "df", args: []string{"-h"}},
		"memory":  {bin: "free", args: []string{"-h"}},
		"uptime":  {bin: "uptime", args: nil},
		"loadavg": {bin: "cat", args: []string{"/proc/loadavg"}},
	}

	spec, ok := allowedMetrics[metric]
	if !ok {
		http.Error(w, `{"error":"unknown metric"}`, http.StatusBadRequest)
		return
	}

	// SAFE: binary and all args are server-controlled from allowlist
	out, _ := exec.Command(spec.bin, spec.args...).Output()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"output": string(out)})
}

func isValidDomain(domain string) bool {
	// Must be a valid hostname
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(domain) {
		return false
	}
	// Must end with an allowed suffix
	for _, suffix := range allowedDomainSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	// Also allow bare IP addresses (for reverse lookups)
	if net.ParseIP(domain) != nil {
		return true
	}
	return false
}

func errStr(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func main() {
	http.HandleFunc("/api/dns", dnsLookupHandler)
	http.HandleFunc("/api/archive", archiveHandler)
	http.HandleFunc("/api/system", systemInfoHandler)
	http.ListenAndServe(":8080", nil)
}
