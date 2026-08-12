package main

import "os"

func build(name string) string {
	target := name
	data, err := os.ReadFile("/srv/reports/" + target)
	if err != nil {
		return ""
	}
	return string(data)
}
