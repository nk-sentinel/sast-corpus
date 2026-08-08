package app

import (
	"os/exec"
)

func Archive(name string) ([]byte, error) {
	line := "tar -cf backup.tar " + name
	return exec.Command("sh", "-c", line).Output()
}
