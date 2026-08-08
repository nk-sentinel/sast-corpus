package app

import (
	"os"
	"path/filepath"
)

const base = "/srv/reports"

func Contents(name string) ([]byte, error) {
	target := filepath.Join(base, name)
	return os.ReadFile(target)
}
