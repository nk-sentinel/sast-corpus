package main

import "os/exec"

func build(name string) string {
	params := map[string]string{"target": name, "mode": "summary"}
	return run(params["target"])
}

func run(target string) string {
	_ = exec.Command("sh", "-c", "/usr/bin/report "+target).Run()
	return target
}
