// Fixture: go-gorm-order + go-sprintf-query — GORM Order injection and fmt.Sprintf
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-89
// Pattern: User-controlled ORDER BY in GORM, fmt.Sprintf in database/sql

package main

import (
	"database/sql"
	"fmt"
	"net/http"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name  string
	Email string
}

// VULNERABLE: GORM Order with user-controlled string
func listUsers(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
	sortField := r.URL.Query().Get("sort")
	var users []User
	// ORDER BY cannot be parameterized — user controls SQL structure
	db.Order(sortField).Find(&users)
}

// VULNERABLE: GORM Raw with fmt.Sprintf
func searchUsers(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	var users []User
	// fmt.Sprintf builds raw SQL string
	db.Raw(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)).Scan(&users)
}

// VULNERABLE: database/sql with fmt.Sprintf
func getUserByID(dbConn *sql.DB, w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
	rows, _ := dbConn.Query(query)
	defer rows.Close()
}

// VULNERABLE: GORM Where with fmt.Sprintf
func filterUsers(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	var users []User
	db.Where(fmt.Sprintf("status = '%s'", status)).Find(&users)
}
