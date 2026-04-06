// Fixture: go-template-html-bypass — html/template with template.HTML() type cast bypass
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-79
// Agent: xss
// Pattern: template.HTML() type cast tells html/template to skip escaping for user-controlled data

package main

import (
	"html/template"
	"log"
	"net/http"
)

var dashboardTmpl = template.Must(template.New("dashboard").Parse(`
<!DOCTYPE html>
<html>
<body>
    <div class="announcement">{{.Announcement}}</div>
    <div class="content">{{.Content}}</div>
    <div class="footer">{{.Footer}}</div>
</body>
</html>
`))

type DashboardData struct {
	Announcement template.HTML // Type-cast field — html/template skips escaping
	Content      template.HTML
	Footer       string // Normal string — html/template auto-escapes this
}

// VULNERABLE: template.HTML() type cast on user-controlled input
// html/template trusts template.HTML values as safe, emitting them raw
// Attacker sends: ?announcement=<script>alert(document.cookie)</script>
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	announcement := r.URL.Query().Get("announcement")
	content := r.URL.Query().Get("content")

	data := DashboardData{
		// VULNERABLE: template.HTML() bypass — user input treated as trusted HTML
		Announcement: template.HTML(announcement),
		// VULNERABLE: same pattern on content field
		Content: template.HTML(content),
		Footer:  "Safe footer text",
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

var widgetTmpl = template.Must(template.New("widget").Parse(`
<div class="widget" style="{{.Style}}">
    <a href="{{.Link}}">{{.Label}}</a>
</div>
`))

type WidgetData struct {
	Style template.CSS  // VULNERABLE: template.CSS() skips CSS context escaping
	Link  template.URL  // VULNERABLE: template.URL() skips URL context escaping
	Label string
}

// VULNERABLE: template.CSS() and template.URL() bypass context-specific escaping
// Attacker sends: ?link=javascript:alert(1) or ?style=background:url(javascript:alert(1))
func widgetHandler(w http.ResponseWriter, r *http.Request) {
	data := WidgetData{
		// VULNERABLE: user input cast to template.CSS — allows style injection
		Style: template.CSS(r.URL.Query().Get("style")),
		// VULNERABLE: user input cast to template.URL — allows javascript: URIs
		Link:  template.URL(r.URL.Query().Get("link")),
		Label: r.URL.Query().Get("label"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := widgetTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/widget", widgetHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
