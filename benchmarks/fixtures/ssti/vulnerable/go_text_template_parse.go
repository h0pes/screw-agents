// Fixture: go-text-template-parse — template.Parse(user_input)
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-1336
// Agent: ssti
// Pattern: User input passed as template source to template.New().Parse() or template.Must(template.New().Parse())

package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
)

type PageData struct {
	Title   string
	Content string
	User    string
}

// VULNERABLE: user-controlled template string parsed and executed
// Go's text/template allows calling methods on objects, enabling information disclosure
// Attacker sends: ?layout={{.}} or custom payloads depending on context objects
func widgetHandler(w http.ResponseWriter, r *http.Request) {
	layout := r.URL.Query().Get("layout")
	if layout == "" {
		layout = "<p>Default widget</p>"
	}
	title := r.URL.Query().Get("title")
	if title == "" {
		title = "Widget"
	}

	// VULNERABLE: user-controlled layout is the template source
	tmplSrc := fmt.Sprintf(`<html><body><h1>%s</h1>%s</body></html>`, title, layout)
	tmpl, err := template.New("widget").Parse(tmplSrc)
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	data := PageData{Title: title, Content: "Widget content", User: "admin"}
	tmpl.Execute(w, data)
}

type NotificationData struct {
	Recipient string
	Message   string
	AppConfig map[string]string
}

// VULNERABLE: notification template from POST body parsed as Go template
// Attacker can access exported fields/methods on data passed to Execute
func notificationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	templateBody := r.FormValue("template")
	recipient := r.FormValue("recipient")

	if templateBody == "" {
		templateBody = "<p>Hello {{.Recipient}}, you have a new notification.</p>"
	}

	// VULNERABLE: user-controlled templateBody is parsed as Go template
	tmpl, err := template.New("notification").Parse(templateBody)
	if err != nil {
		http.Error(w, "template parse error", http.StatusInternalServerError)
		return
	}

	data := NotificationData{
		Recipient: recipient,
		Message:   "You have updates",
		AppConfig: map[string]string{
			"db_host":  "prod-db.internal",
			"api_key":  "sk-secret-key-12345",
			"admin_pw": "supersecret",
		},
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		http.Error(w, "template exec error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(buf.String()))
}

func main() {
	http.HandleFunc("/widget", widgetHandler)
	http.HandleFunc("/api/notification", notificationHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
