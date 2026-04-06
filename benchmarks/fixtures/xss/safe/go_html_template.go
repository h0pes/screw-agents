// Fixture: go-html-template — Using html/template correctly with html.EscapeString()
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-79
// Agent: xss
// Pattern: html/template provides contextual auto-escaping; html.EscapeString() for manual encoding

package main

import (
	"html"
	"html/template" // SAFE: html/template provides contextual auto-escaping
	"log"
	"net/http"
)

// SAFE: html/template auto-escapes based on context (HTML body, attribute, JS, CSS, URL)
// Unlike text/template, html/template understands HTML structure and applies
// context-appropriate encoding to all template variables
var profileTmpl = template.Must(template.New("profile").Parse(`
<!DOCTYPE html>
<html>
<body>
    <h1>Profile: {{.Name}}</h1>
    <p>Bio: {{.Bio}}</p>
    <p>Location: {{.Location}}</p>
    <a href="/user/{{.Name}}">Permalink</a>
</body>
</html>
`))

type ProfileData struct {
	Name     string
	Bio      string
	Location string
}

// SAFE: html/template auto-escapes .Name, .Bio, .Location in all contexts
// Input "<script>alert(1)</script>" becomes "&lt;script&gt;alert(1)&lt;/script&gt;"
func profileHandler(w http.ResponseWriter, r *http.Request) {
	data := ProfileData{
		Name:     r.URL.Query().Get("name"),
		Bio:      r.URL.Query().Get("bio"),
		Location: r.URL.Query().Get("location"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := profileTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

var searchTmpl = template.Must(template.New("search").Parse(`
<!DOCTYPE html>
<html>
<body>
    <h1>Search Results</h1>
    <p>Showing results for: {{.Query}}</p>
    <form>
        <input type="text" name="q" value="{{.Query}}">
        <button type="submit">Search</button>
    </form>
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

// SAFE: html/template escapes .Query in both HTML body and attribute contexts
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
	if err := searchTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// SAFE: html.EscapeString() for cases where manual encoding is needed
func errorHandler(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("message")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// SAFE: html.EscapeString() encodes <, >, &, ", ' to HTML entities
	escapedMessage := html.EscapeString(message)
	w.Write([]byte("<html><body><p>Error: " + escapedMessage + "</p></body></html>"))
}

func main() {
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/error", errorHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
