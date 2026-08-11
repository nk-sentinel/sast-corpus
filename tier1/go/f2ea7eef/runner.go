package app

import (
	"errors"
	"os/exec"
	"strings"
)

func Mirror(source string) ([]byte, error) {
	if strings.HasPrefix(source, "-") {
		return nil, errors.New("rejected")
	}
	return exec.Command("git", "clone", "--", source, "/tmp/mirror").Output()
}
