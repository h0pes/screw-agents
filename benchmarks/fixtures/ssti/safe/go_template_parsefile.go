// Fixture: go-template-parsefile — template.ParseFiles() with user data in struct
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-1336
// Agent: ssti
// Pattern: Template loaded from file via ParseFiles()/ParseGlob(), user input flows as data only

package main

import (
	"html/template"
	"log"
	"net/http"
)

type PageData struct {
	Title   string
	Content string
	User    string
}

type SearchData struct {
	Query      string
	Results    []SearchResult
	Page       int
	TotalPages int
}

type SearchResult struct {
	Title   string
	Snippet string
	URL     string
}

// Pre-parse templates at startup from files
var templates = template.Must(template.ParseGlob("templates/*.html"))

// SAFE: Template loaded from file, user input is data in the PageData struct
// User input cannot alter template structure, only fills in designated placeholders
func profileHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		username = "Guest"
	}
	bio := r.URL.Query().Get("bio")
	if bio == "" {
		bio = "No bio provided"
	}

	data := PageData{
		Title:   "Profile - " + username,
		Content: bio,
		User:    username,
	}

	// SAFE: executing pre-parsed file template with user data as struct fields
	if err := templates.ExecuteTemplate(w, "profile.html", data); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// SAFE: Search results rendered from file template
func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		query = ""
	}

	results := make([]SearchResult, 0, 10)
	for i := 1; i <= 10; i++ {
		results = append(results, SearchResult{
			Title:   "Result",
			Snippet: "Match for query...",
			URL:     "/item",
		})
	}

	data := SearchData{
		Query:      query,
		Results:    results,
		Page:       1,
		TotalPages: 5,
	}

	// SAFE: file-based template, user input is data only
	if err := templates.ExecuteTemplate(w, "search.html", data); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// SAFE: Dashboard with file template and user data
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "overview"
	}

	data := struct {
		UserID    string
		ActiveTab string
		Stats     map[string]int
	}{
		UserID:    userID,
		ActiveTab: tab,
		Stats: map[string]int{
			"posts":    42,
			"comments": 128,
			"likes":    567,
		},
	}

	// SAFE: template from file, tab and userID are data, not template source
	if err := templates.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
