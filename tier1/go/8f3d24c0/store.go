package app

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func Lookup(code string) (string, error) {
	statement := fmt.Sprintf("SELECT status FROM orders WHERE code = '%s'", code)
	var status string
	err := db.QueryRow(statement).Scan(&status)
	return status, err
}
