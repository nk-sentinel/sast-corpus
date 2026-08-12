package main

func build(code string) string {
	holder := []string{}
	same := &holder
	holder = append(holder, code)
	return run("SELECT status FROM orders WHERE code = '" + (*same)[0] + "'")
}

func run(statement string) string {
	return statement
}
