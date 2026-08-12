package main

func build(code string) string {
	compose := func(value string) string {
		return "SELECT status FROM orders WHERE code = $1"
	}
	return apply(compose, code)
}

func apply(step func(string) string, value string) string {
	return run(step(value), value)
}

func run(statement string, value string) string {
	return statement + "|" + value
}
