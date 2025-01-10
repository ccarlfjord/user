package rest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

func JSON(w http.ResponseWriter, status int, body interface{}) {
	json, err := json.Marshal(body)
	if err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(json)
}

func PlainText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	w.Write([]byte(body))
}

func validateContentTypeJSON(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get("Content-Type") == "application/json" {
		return nil
	}
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte("Content-Type must be application/json"))
	return errors.New("content type not JSON")
}
