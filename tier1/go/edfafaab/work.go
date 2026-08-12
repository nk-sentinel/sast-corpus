package main

func build(code string) string {
	return run("SELECT status FROM orders WHERE code = $1", code)
}

func run(statement string, value string) string {
	return statement + "|" + value
}
