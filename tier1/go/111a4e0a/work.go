package main

import "os"

type request struct {
	name string
}

func build(name string) string {
	r := &request{}
	r.name = name
	return read(r)
}

func read(r *request) string {
	data, err := os.ReadFile("/srv/reports/" + r.name)
	if err != nil {
		return ""
	}
	return string(data)
}
