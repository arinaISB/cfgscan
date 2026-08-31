// Package httpapi exposes configuration analysis over HTTP.
package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"cfgscan/internal/analyzer"
	"cfgscan/internal/app"
)

const maxRequestBodyBytes int64 = 1 << 20

type response struct {
	Problems []analyzer.Problem `json:"problems"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// NewHandler returns the HTTP API handler backed by service.
func NewHandler(service app.Service) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/analyze" {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}

			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
			data, err := io.ReadAll(r.Body)
			if err != nil {
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
					return
				}
				writeError(w, http.StatusInternalServerError, "read request body")
				return
			}
			if len(strings.TrimSpace(string(data))) == 0 {
				writeError(w, http.StatusBadRequest, "request body is empty")
				return
			}

			problems, err := service.Analyze(r.Context(), bytes.NewReader(data))
			if err != nil {
				var parseErr *app.ParseError
				if errors.As(err, &parseErr) {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				writeError(w, http.StatusInternalServerError, "analyze configuration")
				return
			}
			for index := range problems {
				problems[index].Source = "request"
			}
			writeJSON(w, http.StatusOK, response{Problems: problems})
		},
	)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
