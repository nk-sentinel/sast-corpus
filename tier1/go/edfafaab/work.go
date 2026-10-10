package main

import "database/sql"

func build(code string) string {
	return run("SELECT status FROM orders WHERE code = $1", code)
}

func run(statement string, value string) string {
	db, err := sql.Open("sqlite3", "app.db")
	if err != nil {
		return ""
	}
	rows, err := db.Query(statement, value)
	if err != nil {
		return ""
	}
	defer rows.Close()
	return statement
}
