package app

import (
	"net/http"
)

func init() {
	http.HandleFunc("/show", Show)
}

func Show(w http.ResponseWriter, r *http.Request) {
	status, err := Lookup(r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	w.Write([]byte(status))
}
