package main

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
	return statement
}
