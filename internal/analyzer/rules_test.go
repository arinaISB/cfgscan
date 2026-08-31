package analyzer

import (
	"context"
	"errors"
	"strings"
	"testing"

	"cfgscan/internal/parser"
)

func TestRulesDetectExpectedConfiguration(t *testing.T) {
	tests := []struct {
		name         string
		rule         Rule
		document     parser.Document
		wantPath     string
		wantSeverity Severity
	}{
		{
			name:     "debug log level regardless of location",
			rule:     DebugLoggingRule{},
			document: parser.Document{Value: map[string]any{"feature": map[string]any{"logging_level": "debug"}}},
			wantPath: "feature.logging_level", wantSeverity: SeverityLow,
		},
		{
			name:     "plaintext password in array",
			rule:     PlaintextPasswordRule{},
			document: parser.Document{Value: map[string]any{"users": []any{map[string]any{"password": "literal-value"}}}},
			wantPath: "users[0].password", wantSeverity: SeverityHigh,
		},
		{
			name:     "unrestricted bind",
			rule:     UnrestrictedBindRule{},
			document: parser.Document{Value: map[string]any{"servers": []any{map[string]any{"bind_address": "0.0.0.0:8080"}}}},
			wantPath: "servers[0].bind_address", wantSeverity: SeverityMedium,
		},
		{
			name:     "disabled tls",
			rule:     DisabledTLSRule{},
			document: parser.Document{Value: map[string]any{"client": map[string]any{"verify_tls": false}}},
			wantPath: "client.verify_tls", wantSeverity: SeverityHigh,
		},
		{
			name:     "disabled TLS through tls enabled",
			rule:     DisabledTLSRule{},
			document: parser.Document{Value: map[string]any{"client": map[string]any{"tls_enabled": false}}},
			wantPath: "client.tls_enabled", wantSeverity: SeverityHigh,
		},
		{
			name:     "weak algorithm",
			rule:     WeakAlgorithmRule{},
			document: parser.Document{Value: map[string]any{"storage": map[string]any{"digest-algorithm": "SHA-1"}}},
			wantPath: "storage.digest-algorithm", wantSeverity: SeverityHigh,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			problems, err := test.rule.Check(context.Background(), test.document)
			if err != nil {
				t.Fatal(err)
			}
			if len(problems) != 1 {
				t.Fatalf("findings = %#v, want one", problems)
			}
			problem := problems[0]
			if problem.RuleID != test.rule.ID() || problem.Path != test.wantPath || problem.Severity != test.wantSeverity {
				t.Fatalf("problem = %#v", problem)
			}
		})
	}
}

func TestRulesIgnoreSafeConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		rule     Rule
		document parser.Document
	}{
		{name: "non-logging level", rule: DebugLoggingRule{}, document: parser.Document{Value: map[string]any{"feature": map[string]any{"level": "debug"}}}},
		{name: "login level", rule: DebugLoggingRule{}, document: parser.Document{Value: map[string]any{"login": map[string]any{"level": "debug"}}}},
		{name: "logic level", rule: DebugLoggingRule{}, document: parser.Document{Value: map[string]any{"logic": map[string]any{"level": "debug"}}}},
		{name: "debug logging is not enabled", rule: DebugLoggingRule{}, document: parser.Document{Value: map[string]any{"log_level": "info"}}},
		{name: "external password reference", rule: PlaintextPasswordRule{}, document: parser.Document{Value: map[string]any{"password": "${DATABASE_PASSWORD}", "api_token": "{{ secrets.token }}", "secret": ""}}},
		{name: "restricted bind", rule: UnrestrictedBindRule{}, document: parser.Document{Value: map[string]any{"host": "127.0.0.1"}}},
		{name: "enabled tls", rule: DisabledTLSRule{}, document: parser.Document{Value: map[string]any{"tls": true, "tls_enabled": true, "insecure_skip_verify": false}}},
		{name: "modern algorithm", rule: WeakAlgorithmRule{}, document: parser.Document{Value: map[string]any{"hash_algorithm": "SHA-256", "cipher": "AES-GCM"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			problems, err := test.rule.Check(context.Background(), test.document)
			if err != nil {
				t.Fatal(err)
			}
			if len(problems) != 0 {
				t.Fatalf("findings = %#v, want none", problems)
			}
		})
	}
}

func TestEngineCombinesFindings(t *testing.T) {
	engine := NewEngine(DefaultRules()...)
	document := parser.Document{Value: map[string]any{
		"logging":  map[string]any{"level": "debug"},
		"database": map[string]any{"password": "literal", "host": "0.0.0.0"},
		"client":   map[string]any{"tls_verify": false, "hash_algorithm": "MD5"},
	}}

	problems, err := engine.Analyze(context.Background(), document)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 5 {
		t.Fatalf("findings = %#v, want five", problems)
	}
}

func TestEngineIncludesRuleIDInError(t *testing.T) {
	engine := NewEngine(failingRule{})
	_, err := engine.Analyze(context.Background(), parser.Document{})
	if err == nil || !strings.Contains(err.Error(), `rule "failing-rule"`) {
		t.Fatalf("error = %v, want rule ID", err)
	}
}

type failingRule struct{}

func (failingRule) ID() string { return "failing-rule" }

func (failingRule) Check(context.Context, parser.Document) ([]Problem, error) {
	return nil, errors.New("rule failed")
}
