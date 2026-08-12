package main

import "os"

func build(name string) string {
	target := name
	target = "daily-summary.txt"
	data, err := os.ReadFile("/srv/reports/" + target)
	if err != nil {
		return ""
	}
	return string(data)
}
