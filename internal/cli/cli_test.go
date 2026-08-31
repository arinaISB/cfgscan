package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
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
	openFile := func(path string) (input.Source, io.Closer, error) {
		openedPath = path
		return input.Source{Name: path, Reader: strings.NewReader("valid: true\n")}, io.NopCloser(strings.NewReader("")), nil
	}

	code := Run(context.Background(), []string{"config.yaml"}, strings.NewReader(""), io.Discard, &stderr, app.New(analyzer.NewEngine()), openFile)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if openedPath != "config.yaml" {
		t.Fatalf("opened path = %q, want %q", openedPath, "config.yaml")
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
			if !strings.Contains(stdout.String(), "HIGH [test-rule] service.password: test finding Recommendation: fix it") {
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
