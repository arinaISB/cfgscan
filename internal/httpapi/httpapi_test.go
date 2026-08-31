package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"cfgscan/internal/analyzer"
	"cfgscan/internal/app"
	"cfgscan/internal/parser"
)

func TestAnalyzeReturnsEmptyProblemsForSafeConfiguration(t *testing.T) {
	response := perform(t, app.New(analyzer.NewEngine(analyzer.DefaultRules()...)), http.MethodPost, "/v1/analyze", `{"database":{"host":"127.0.0.1"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	var body struct {
		Problems []analyzer.Problem `json:"problems"`
	}
	decodeBody(t, response, &body)
	if body.Problems == nil || len(body.Problems) != 0 {
		t.Fatalf("problems = %#v, want empty array", body.Problems)
	}
}

func TestAnalyzeReturnsFindingsForJSONAndYAML(t *testing.T) {
	for _, input := range []string{
		`{"database":{"password":"literal"}}`,
		"database:\n  password: literal\n",
	} {
		t.Run(input[:1], func(t *testing.T) {
			response := perform(t, app.New(analyzer.NewEngine(analyzer.DefaultRules()...)), http.MethodPost, "/v1/analyze", input)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.Code)
			}
			var body struct {
				Problems []analyzer.Problem `json:"problems"`
			}
			decodeBody(t, response, &body)
			if len(body.Problems) != 1 {
				t.Fatalf("problems = %#v, want one finding", body.Problems)
			}
			problem := body.Problems[0]
			if problem.Source != "request" || problem.RuleID != "plaintext-password" || problem.Severity != analyzer.SeverityHigh || problem.Path != "database.password" {
				t.Fatalf("problem = %#v, want request plaintext-password finding", problem)
			}
		})
	}
}

func TestAnalyzeRejectsInvalidBody(t *testing.T) {
	for _, body := range []string{"database: [", "", " \n\t "} {
		t.Run("invalid request", func(t *testing.T) {
			response := perform(t, app.New(analyzer.NewEngine()), http.MethodPost, "/v1/analyze", body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", response.Code)
			}
			assertErrorBody(t, response)
		})
	}
}

func TestAnalyzeRejectsBodyOverLimit(t *testing.T) {
	response := perform(t, app.New(analyzer.NewEngine()), http.MethodPost, "/v1/analyze", string(bytes.Repeat([]byte("a"), int(maxRequestBodyBytes+1))))
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", response.Code)
	}
	assertErrorBody(t, response)
}

func TestAnalyzeRejectsUnsupportedMethod(t *testing.T) {
	response := perform(t, app.New(analyzer.NewEngine()), http.MethodGet, "/v1/analyze", "")
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", response.Code)
	}
	if allow := response.Header().Get("Allow"); allow != http.MethodPost {
		t.Fatalf("Allow = %q, want POST", allow)
	}
}

func TestAnalyzeReturnsNotFoundForOtherPath(t *testing.T) {
	response := perform(t, app.New(analyzer.NewEngine()), http.MethodPost, "/other", "valid: true")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
}

func TestAnalyzeReturnsInternalErrorForAnalyzerFailure(t *testing.T) {
	response := perform(t, app.New(failingAnalyzer{}), http.MethodPost, "/v1/analyze", "valid: true")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", response.Code)
	}
	assertErrorBody(t, response)
}

func perform(t *testing.T, service app.Service, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	response := httptest.NewRecorder()
	NewHandler(service).ServeHTTP(response, request)
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	return response
}

func decodeBody(t *testing.T, response *httptest.ResponseRecorder, destination any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), destination); err != nil {
		t.Fatalf("decode response: %v; body = %q", err, response.Body.String())
	}
}

func assertErrorBody(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	decodeBody(t, response, &body)
	if body.Error == "" {
		t.Fatalf("error body = %q, want non-empty error", response.Body.String())
	}
}

type failingAnalyzer struct{}

func (failingAnalyzer) Analyze(context.Context, parser.Document) ([]analyzer.Problem, error) {
	return nil, errors.New("analyzer failed")
}
