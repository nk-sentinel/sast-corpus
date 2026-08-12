package main

import (
	"os"
	"path/filepath"
	"strings"
)

const base = "/srv/reports"

type request struct {
	name string
}

func build(name string) string {
	r := &request{}
	r.name = filepath.Base(name)
	return read(r)
}

func read(r *request) string {
	target := filepath.Clean(filepath.Join(base, r.name))
	if !strings.HasPrefix(target, base+string(os.PathSeparator)) {
		return ""
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return ""
	}
	return string(data)
}
