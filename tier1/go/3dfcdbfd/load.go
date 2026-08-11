package app

import (
	"bytes"
	"encoding/gob"
)

type Settings struct {
	Name string
	Admin bool
}

func Render(blob string) string {
	var settings Settings
	gob.NewDecoder(bytes.NewBufferString(blob)).Decode(&settings)
	if settings.Admin {
		return "admin"
	}
	return settings.Name
}
