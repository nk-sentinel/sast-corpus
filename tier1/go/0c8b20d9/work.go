package main

import "os/exec"

var allowed = map[string]string{"daily": "daily", "weekly": "weekly"}

func build(name string) string {
	target, ok := allowed[name]
	if !ok {
		return ""
	}
	return run(target)
}

func run(target string) string {
	_ = exec.Command("/usr/bin/report", target).Run()
	return target
}
