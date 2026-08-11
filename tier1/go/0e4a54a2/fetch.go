package app

import (
	"io"
	"net/http"
	"net/url"
)

var permitted = map[string]bool{"api.example.com": true}

func Render(target string) string {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || !permitted[parsed.Hostname()] {
		return ""
	}
	response, err := http.Get(target)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return string(body)
}
