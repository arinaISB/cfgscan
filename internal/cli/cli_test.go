package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfgscan/internal/analyzer"
	"cfgscan/internal/app"
	"cfgscan/internal/input"
	"cfgscan/internal/parser"
)

func TestRunRequiresPathWithoutStdin(t *testing.T) {
	var stderr bytes.Buffer
	code := Run(context.Background(), nil, strings.NewReader(""), io.Discard, &stderr, app.New(analyzer.NewEngine()), unusedOpenFile)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "configuration file path is required") {
		t.Fatalf("error = %q, want missing-path message", stderr.String())
	}
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want options
	}{
		{name: "short silent", args: []string{"-s", "config.yaml"}, want: options{silent: true, path: "config.yaml"}},
		{name: "long silent", args: []string{"--silent", "config.yaml"}, want: options{silent: true, path: "config.yaml"}},
		{name: "stdin", args: []string{"--stdin"}, want: options{stdin: true}},
		{name: "HTTP server", args: []string{"--http-addr", ":8080"}, want: options{httpAddr: ":8080", httpServer: true}},
		{name: "gRPC server", args: []string{"--grpc-addr", ":9090"}, want: options{grpcAddr: ":9090", grpcServer: true}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parse(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("parse(%q) = %#v, want %#v", test.args, got, test.want)
			}
		})
	}
}

func TestParseRejectsGRPCServerCombinations(t *testing.T) {
	for _, args := range [][]string{
		{"--grpc-addr", ":9090", "config.yaml"},
		{"--grpc-addr", ":9090", "--stdin"},
		{"--grpc-addr", ":9090", "--silent"},
		{"--grpc-addr", ":9090", "-s"},
		{"--grpc-addr", ":9090", "--http-addr", ":8080"},
	} {
		if _, err := parse(args); err == nil {
			t.Fatalf("parse(%q) succeeded, want usage error", args)
		}
	}
}

func TestParseRejectsHTTPServerCombinations(t *testing.T) {
	for _, args := range [][]string{
		{"--http-addr", ":8080", "config.yaml"},
		{"--http-addr", ":8080", "--stdin"},
		{"--http-addr", ":8080", "--silent"},
		{"--http-addr", ":8080", "-s"},
	} {
		if _, err := parse(args); err == nil {
			t.Fatalf("parse(%q) succeeded, want usage error", args)
		}
	}
}

func TestRunReadsStdin(t *testing.T) {
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"--stdin"}, strings.NewReader("valid: true\n"), io.Discard, &stderr, app.New(analyzer.NewEngine()), unusedOpenFile)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunOpensConfigurationFile(t *testing.T) {
	var stderr bytes.Buffer
	openedPath := ""
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("valid: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	openFile := func(path string) (input.Source, io.Closer, error) {
		openedPath = path
		return input.Source{Name: path, Reader: strings.NewReader("valid: true\n")}, io.NopCloser(strings.NewReader("")), nil
	}

	code := Run(context.Background(), []string{path}, strings.NewReader(""), io.Discard, &stderr, app.New(analyzer.NewEngine()), openFile)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if openedPath != path {
		t.Fatalf("opened path = %q, want %q", openedPath, path)
	}
}

func TestRunScansDirectoryInOrderAndSetsSources(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.yaml")
	second := filepath.Join(dir, "nested", "b.json")
	for path, contents := range map[string]string{
		first:                             "database:\n  password: literal\n",
		second:                            `{"database":{"password":"literal"}}`,
		filepath.Join(dir, "ignored.txt"): "database:\n  password: literal\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--silent", dir}, strings.NewReader(""), &stdout, &stderr, app.New(analyzer.NewEngine(analyzer.DefaultRules()...)), input.OpenFile)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, first+": HIGH [plaintext-password]") || !strings.Contains(output, second+": HIGH [plaintext-password]") {
		t.Fatalf("output = %q, want findings with both sources", output)
	}
	if strings.Contains(output, "ignored.txt") || strings.Index(output, first+":") > strings.Index(output, second+":") {
		t.Fatalf("output = %q, want supported files only in lexical order", output)
	}
}

func TestRunDirectoryWithoutSupportedConfigurationsSucceeds(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a config"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{dir}, strings.NewReader(""), &stdout, &stderr, app.New(analyzer.NewEngine()), input.OpenFile)
	if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestRunReportsInputReadError(t *testing.T) {
	var stderr bytes.Buffer
	brokenInput := errReader{err: errors.New("read failed")}
	code := Run(context.Background(), []string{"--stdin"}, brokenInput, io.Discard, &stderr, app.New(analyzer.NewEngine()), unusedOpenFile)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "read failed") {
		t.Fatalf("error = %q, want read error", stderr.String())
	}
}

func TestRunReturnsFindingExitCodeUnlessSilent(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{name: "normal", args: []string{"--stdin"}, want: 1},
		{name: "silent", args: []string{"--stdin", "--silent"}, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			service := app.New(staticAnalyzer{problems: []analyzer.Problem{{
				RuleID:         "test-rule",
				Severity:       analyzer.SeverityHigh,
				Path:           "service.password",
				Message:        "test finding",
				Recommendation: "fix it",
			}}})

			code := Run(context.Background(), test.args, strings.NewReader("valid: true\n"), &stdout, &stderr, service, unusedOpenFile)
			if code != test.want {
				t.Fatalf("exit code = %d, want %d; stderr = %q", code, test.want, stderr.String())
			}
			if !strings.Contains(stdout.String(), "stdin: HIGH [test-rule] service.password: test finding Recommendation: fix it") {
				t.Fatalf("output = %q, want formatted finding", stdout.String())
			}
		})
	}
}

func unusedOpenFile(string) (input.Source, io.Closer, error) {
	return input.Source{}, nil, errors.New("openFile must not be called")
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

type staticAnalyzer struct {
	problems []analyzer.Problem
}

func (a staticAnalyzer) Analyze(context.Context, parser.Document) ([]analyzer.Problem, error) {
	return a.problems, nil
}
