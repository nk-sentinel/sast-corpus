package app

import (
	"os/exec"
)

func Archive(name string) ([]byte, error) {
	return exec.Command("tar", "-cf", "backup.tar", name).Output()
}
