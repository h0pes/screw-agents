// Fixture: go-text-template — Using text/template instead of html/template (no escaping)
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-79
// Agent: xss
// Pattern: Import of text/template for HTML output — text/template performs zero HTML escaping

package main

import (
	"log"
	"net/http"
	"text/template" // VULNERABLE: text/template has NO HTML escaping
)

// VULNERABLE: text/template does not perform any HTML entity encoding
// Unlike html/template, all template variables are emitted raw
// Attacker sends: GET /profile?name=<script>alert(1)</script>
var profileTmpl = template.Must(template.New("profile").Parse(`
<!DOCTYPE html>
<html>
<body>
    <h1>Profile: {{.Name}}</h1>
    <p>Bio: {{.Bio}}</p>
    <p>Location: {{.Location}}</p>
</body>
</html>
`))

type ProfileData struct {
	Name     string
	Bio      string
	Location string
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	data := ProfileData{
		Name:     r.URL.Query().Get("name"),
		Bio:      r.URL.Query().Get("bio"),
		Location: r.URL.Query().Get("location"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// VULNERABLE: text/template renders all values without HTML escaping
	if err := profileTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// VULNERABLE: text/template with inline parsing from user data
// Attacker sends: GET /search?q=<img src=x onerror=alert(document.cookie)>
var searchTmpl = template.Must(template.New("search").Parse(`
<!DOCTYPE html>
<html>
<body>
    <h1>Search Results</h1>
    <p>Showing results for: {{.Query}}</p>
    <ul>
    {{range .Results}}
        <li>{{.Title}} — <em>{{.Snippet}}</em></li>
    {{end}}
    </ul>
</body>
</html>
`))

type SearchResult struct {
	Title   string
	Snippet string
}

type SearchData struct {
	Query   string
	Results []SearchResult
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	data := SearchData{
		Query: query,
		Results: []SearchResult{
			{Title: "Result 1", Snippet: "Match for: " + query},
			{Title: "Result 2", Snippet: "Related to: " + query},
		},
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// VULNERABLE: user-controlled query rendered without escaping
	if err := searchTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/search", searchHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
