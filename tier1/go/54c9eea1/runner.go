package app

import (
	"os/exec"
)

func Mirror(source string) ([]byte, error) {
	return exec.Command("git", "clone", source, "/tmp/mirror").Output()
}
