package app

import (
	"database/sql"
)

var db *sql.DB

func Lookup(code string) (string, error) {
	statement := "SELECT status FROM orders WHERE code = $1"
	var status string
	err := db.QueryRow(statement, code).Scan(&status)
	return status, err
}
