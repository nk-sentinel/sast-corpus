package main

import "database/sql"

func build(code string) string {
	holder := []string{}
	same := &holder
	holder = append(holder, code)
	return run("SELECT status FROM orders WHERE code = '" + (*same)[0] + "'")
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
