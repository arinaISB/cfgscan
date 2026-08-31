package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"cfgscan/internal/analyzer"
	"cfgscan/internal/parser"
)

func TestAnalyzeReadsAndParsesInputBeforeCallingAnalyzer(t *testing.T) {
	recorder := &recordingAnalyzer{}
	service := New(recorder)

	problems, err := service.Analyze(context.Background(), strings.NewReader("service:\n  enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Fatalf("problems = %#v, want no problems", problems)
	}
	want := parser.Document{Value: map[string]any{"service": map[string]any{"enabled": true}}}
	if !reflect.DeepEqual(recorder.document, want) {
		t.Fatalf("document = %#v, want %#v", recorder.document, want)
	}
}

func TestAnalyzeReportsReadError(t *testing.T) {
	service := New(analyzer.NewEngine())
	_, err := service.Analyze(context.Background(), errorReader{err: errors.New("read failed")})
	if err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("error = %v, want read error", err)
	}
}

type recordingAnalyzer struct {
	document parser.Document
}

func (r *recordingAnalyzer) Analyze(_ context.Context, document parser.Document) ([]analyzer.Problem, error) {
	r.document = document
	return []analyzer.Problem{}, nil
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }
