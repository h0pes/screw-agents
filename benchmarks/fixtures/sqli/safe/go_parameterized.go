// Fixture: Safe parameterized queries — Go
// Expected: TRUE NEGATIVE (must NOT be flagged)
// Pattern: database/sql positional params, GORM Where with ?, GORM struct query

package main

import (
	"database/sql"
	"net/http"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name  string
	Email string
}

// SAFE: database/sql with positional parameters
func getUserByID(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	row := db.QueryRow("SELECT name, email FROM users WHERE id = $1", id)
	var name, email string
	row.Scan(&name, &email)
}

// SAFE: GORM Where with placeholder
func searchUsers(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	var users []User
	db.Where("name = ?", name).Find(&users)
}

// SAFE: GORM struct query — auto-parameterized
func filterUsers(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	var users []User
	db.Where(&User{Email: email}).Find(&users)
}

// SAFE: GORM Raw with placeholder
func rawQuery(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	var users []User
	db.Raw("SELECT * FROM users WHERE status = ?", status).Scan(&users)
}

// SAFE: Allowlisted ORDER BY
func sortedUsers(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
	sortParam := r.URL.Query().Get("sort")
	allowedSort := map[string]string{
		"name":  "name",
		"email": "email",
		"date":  "created_at",
	}
	sortCol, ok := allowedSort[sortParam]
	if !ok {
		sortCol = "created_at"
	}
	var users []User
	// Safe: sortCol is server-controlled (from allowlist map)
	db.Order(sortCol).Find(&users)
}

// SAFE: fmt.Sprintf with %d only (integer formatting, not %s)
func countByStatus(db *sql.DB, status int) {
	query := fmt.Sprintf("SELECT COUNT(*) FROM users WHERE status = %d", status)
	db.QueryRow(query)
}
