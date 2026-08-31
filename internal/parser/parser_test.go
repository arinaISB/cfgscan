package parser

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestParseJSON(t *testing.T) {
	document, err := Parse([]byte(`{"service":{"enabled":true,"port":8080},"names":["api","web"]}`))
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]any{
		"service": map[string]any{"enabled": true, "port": json.Number("8080")},
		"names":   []any{"api", "web"},
	}
	if !reflect.DeepEqual(document.Value, want) {
		t.Fatalf("Value = %#v, want %#v", document.Value, want)
	}
}

func TestParseYAML(t *testing.T) {
	document, err := Parse([]byte("service:\n  enabled: true\n  port: 8080\nnames:\n  - api\n  - web\n"))
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]any{
		"service": map[string]any{"enabled": true, "port": 8080},
		"names":   []any{"api", "web"},
	}
	if !reflect.DeepEqual(document.Value, want) {
		t.Fatalf("Value = %#v, want %#v", document.Value, want)
	}
}

func TestParseYAMLNormalizesMapKeysToStrings(t *testing.T) {
	document, err := Parse([]byte("1: one\ntrue: yes\n"))
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]any{"1": "one", "true": "yes"}
	if !reflect.DeepEqual(document.Value, want) {
		t.Fatalf("Value = %#v, want %#v", document.Value, want)
	}
}

func TestParseRejectsInvalidInput(t *testing.T) {
	_, err := Parse([]byte("key: [unterminated"))
	if err == nil {
		t.Fatal("Parse() error = nil, want an error")
	}
	if !strings.Contains(err.Error(), "invalid JSON") || !strings.Contains(err.Error(), "invalid YAML") {
		t.Fatalf("error = %q, want JSON and YAML context", err)
	}
}

func TestParseEmptyDocument(t *testing.T) {
	document, err := Parse([]byte("\n# a comment\n"))
	if err != nil {
		t.Fatal(err)
	}
	if document.Value != nil {
		t.Fatalf("Value = %#v, want nil", document.Value)
	}
}

func TestParseRejectsMultipleYAMLDocuments(t *testing.T) {
	_, err := Parse([]byte("one: 1\n---\ntwo: 2\n"))
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("error = %v, want multiple-documents error", err)
	}
}
