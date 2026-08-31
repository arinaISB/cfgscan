package analyzer

import (
	"context"
	"strings"

	"cfgscan/internal/parser"
)

const (
	debugLoggingRuleID      = "debug-logging"
	plaintextPasswordRuleID = "plaintext-password"
	unrestrictedBindRuleID  = "unrestricted-bind"
	disabledTLSRuleID       = "disabled-tls"
	weakAlgorithmRuleID     = "weak-algorithm"
)

// DefaultRules returns the standard set of configuration security rules.
func DefaultRules() []Rule {
	return []Rule{
		DebugLoggingRule{},
		PlaintextPasswordRule{},
		UnrestrictedBindRule{},
		DisabledTLSRule{},
		WeakAlgorithmRule{},
	}
}

// DebugLoggingRule detects debug-level logging settings.
type DebugLoggingRule struct{}

func (DebugLoggingRule) ID() string { return debugLoggingRuleID }

func (DebugLoggingRule) Check(_ context.Context, document parser.Document) ([]Problem, error) {
	return findings(
		document, debugLoggingRuleID, func(node Node) *Problem {
			value, ok := node.Value.(string)
			if !ok || !isLoggingLevelNode(node) || !strings.EqualFold(strings.TrimSpace(value), "debug") {
				return nil
			}
			return &Problem{
				Severity:       SeverityLow,
				Path:           node.Path,
				Message:        "debug logging is enabled",
				Recommendation: "Use info or a higher log level in production.",
			}
		},
	)
}

// PlaintextPasswordRule detects literal values in password-like fields.
type PlaintextPasswordRule struct{}

func (PlaintextPasswordRule) ID() string { return plaintextPasswordRuleID }

func (PlaintextPasswordRule) Check(_ context.Context, document parser.Document) ([]Problem, error) {
	return findings(
		document, plaintextPasswordRuleID, func(node Node) *Problem {
			value, ok := node.Value.(string)
			if !ok || !isSensitiveKey(node.Key) || isExternalSecretReference(value) || strings.TrimSpace(value) == "" {
				return nil
			}
			return &Problem{
				Severity:       SeverityHigh,
				Path:           node.Path,
				Message:        "a literal secret is stored in the configuration",
				Recommendation: "Load this value from a secret manager or an environment variable.",
			}
		},
	)
}

// UnrestrictedBindRule detects services bound to all IPv4 interfaces.
type UnrestrictedBindRule struct{}

func (UnrestrictedBindRule) ID() string { return unrestrictedBindRuleID }

func (UnrestrictedBindRule) Check(_ context.Context, document parser.Document) ([]Problem, error) {
	return findings(
		document, unrestrictedBindRuleID, func(node Node) *Problem {
			value, ok := node.Value.(string)
			if !ok || !isBindKey(node.Key) || !isUnrestrictedAddress(value) {
				return nil
			}
			return &Problem{
				Severity:       SeverityMedium,
				Path:           node.Path,
				Message:        "service is bound to all network interfaces",
				Recommendation: "Bind to a specific private interface or restrict access with a firewall.",
			}
		},
	)
}

// DisabledTLSRule detects explicit settings that disable TLS protection.
type DisabledTLSRule struct{}

func (DisabledTLSRule) ID() string { return disabledTLSRuleID }

func (DisabledTLSRule) Check(_ context.Context, document parser.Document) ([]Problem, error) {
	return findings(
		document, disabledTLSRuleID, func(node Node) *Problem {
			value, ok := node.Value.(bool)
			if !ok || !isDisabledTLSSetting(node.Key, value) {
				return nil
			}
			return &Problem{
				Severity:       SeverityHigh,
				Path:           node.Path,
				Message:        "TLS certificate verification is disabled",
				Recommendation: "Enable TLS and certificate verification.",
			}
		},
	)
}

// WeakAlgorithmRule detects known weak cryptographic algorithms.
type WeakAlgorithmRule struct{}

func (WeakAlgorithmRule) ID() string { return weakAlgorithmRuleID }

func (WeakAlgorithmRule) Check(_ context.Context, document parser.Document) ([]Problem, error) {
	return findings(
		document, weakAlgorithmRuleID, func(node Node) *Problem {
			value, ok := node.Value.(string)
			if !ok || !isAlgorithmKey(node.Key) || !containsWeakAlgorithm(value) {
				return nil
			}
			return &Problem{
				Severity:       SeverityHigh,
				Path:           node.Path,
				Message:        "a weak cryptographic algorithm is configured",
				Recommendation: "Use a modern algorithm such as SHA-256, AES-GCM, or an approved equivalent.",
			}
		},
	)
}

func findings(document parser.Document, ruleID string, match func(Node) *Problem) ([]Problem, error) {
	problems := make([]Problem, 0)
	err := Walk(
		document, func(node Node) error {
			if problem := match(node); problem != nil {
				problem.RuleID = ruleID
				problems = append(problems, *problem)
			}
			return nil
		},
	)
	return problems, err
}

func isLoggingLevelNode(node Node) bool {
	normalizedKey := normalizeKey(node.Key)
	if normalizedKey != "level" {
		return strings.Contains(normalizedKey, "log") && strings.HasSuffix(normalizedKey, "level")
	}
	return hasLoggingBranch(node.Path)
}

func hasLoggingBranch(path string) bool {
	segments := strings.Split(path, ".")
	for _, segment := range segments[:len(segments)-1] {
		if bracket := strings.Index(segment, "["); bracket >= 0 {
			segment = segment[:bracket]
		}
		normalized := normalizeKey(segment)
		if normalized == "log" || normalized == "logs" || normalized == "logging" || normalized == "logger" ||
			strings.HasSuffix(normalized, "logging") {
			return true
		}
	}
	return false
}

func isSensitiveKey(key string) bool {
	normalized := normalizeKey(key)
	for _, suffix := range []string{"password", "passwd", "secret", "token"} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func isExternalSecretReference(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return strings.HasPrefix(value, "${") || strings.HasPrefix(value, "{{") ||
		strings.HasPrefix(value, "$(") || strings.HasPrefix(value, "$") ||
		strings.HasPrefix(value, "env:") || strings.HasPrefix(value, "vault://") ||
		strings.HasPrefix(value, "secret://") || strings.HasPrefix(value, "ssm://") ||
		strings.HasPrefix(value, "awssecrets://")
}

func isBindKey(key string) bool {
	normalized := normalizeKey(key)
	for _, suffix := range []string{"host", "address", "bind", "listen"} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func isUnrestrictedAddress(value string) bool {
	value = strings.TrimSpace(value)
	return value == "0.0.0.0" || strings.HasPrefix(value, "0.0.0.0:")
}

func isDisabledTLSSetting(key string, value bool) bool {
	normalized := normalizeKey(key)
	return (!value && (normalized == "tls" || normalized == "tlsenabled" || normalized == "verifytls" || normalized == "tlsverify")) ||
		(value && normalized == "insecureskipverify")
}

func isAlgorithmKey(key string) bool {
	normalized := normalizeKey(key)
	return strings.Contains(normalized, "algorithm") || strings.Contains(normalized, "digest") ||
		strings.Contains(normalized, "hash") || strings.Contains(normalized, "cipher")
}

func containsWeakAlgorithm(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	compact := normalizeKey(value)
	if strings.Contains(compact, "md5") || strings.Contains(compact, "sha1") ||
		strings.Contains(compact, "rc4") || strings.Contains(compact, "3des") {
		return true
	}
	for _, token := range strings.FieldsFunc(
		value, func(character rune) bool {
			return (character < 'a' || character > 'z') && (character < '0' || character > '9')
		},
	) {
		if token == "des" || token == "desede" || token == "tripledes" {
			return true
		}
	}
	return false
}

func normalizeKey(key string) string {
	key = strings.ToLower(key)
	var normalized strings.Builder
	for _, character := range key {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			normalized.WriteRune(character)
		}
	}
	return normalized.String()
}
