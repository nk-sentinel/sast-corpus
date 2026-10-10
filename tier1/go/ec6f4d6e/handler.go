package app

import (
	"net/http"
)

func init() {
	http.HandleFunc("/show", Show)
}

func Show(w http.ResponseWriter, r *http.Request) {
	body, err := Contents(r.URL.Query().Get("name"))
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	w.Write(body)
}
