package main

import "database/sql"

func build(code string) string {
	compose := func(value string) string {
		return "SELECT status FROM orders WHERE code = '" + value + "'"
	}
	return apply(compose, code)
}

func apply(step func(string) string, value string) string {
	return run(step(value))
}

func run(statement string) string {
	db, err := sql.Open("sqlite3", "app.db")
	if err != nil {
		return ""
	}
	rows, err := db.Query(statement)
	if err != nil {
		return ""
	}
	defer rows.Close()
	return statement
}
