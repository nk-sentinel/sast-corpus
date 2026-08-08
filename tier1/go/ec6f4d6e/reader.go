package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const base = "/srv/reports"

func Contents(name string) ([]byte, error) {
	target := filepath.Join(base, filepath.Base(name))
	if !strings.HasPrefix(target, base+string(filepath.Separator)) {
		return nil, errors.New("rejected")
	}
	return os.ReadFile(target)
}
