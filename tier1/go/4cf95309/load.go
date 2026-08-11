package app

import "encoding/json"

type Settings struct {
	Name string `json:"name"`
}

func Render(blob string) string {
	var settings Settings
	json.Unmarshal([]byte(blob), &settings)
	return settings.Name
}
