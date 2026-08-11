package app

import (
	"io"
	"net/http"
)

func Render(target string) string {
	response, err := http.Get(target)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return string(body)
}
