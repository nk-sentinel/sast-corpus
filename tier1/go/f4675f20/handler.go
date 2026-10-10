package app

import (
	"net/http"
)

func init() {
	http.HandleFunc("/show", Show)
}

func Show(w http.ResponseWriter, r *http.Request) {
	out, err := Archive(r.URL.Query().Get("name"))
	if err != nil {
		http.Error(w, "archive failed", http.StatusInternalServerError)
		return
	}
	w.Write(out)
}
