// Package analyzer contains configuration-analysis contracts and implementations.
package analyzer

import (
	"context"

	"cfgscan/internal/parser"
)

// Severity describes the impact level of a finding.
type Severity string

const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

// Problem is a security finding produced by an Analyzer.
type Problem struct {
	// Source identifies the input from which this finding was obtained.
	Source         string
	RuleID         string
	Severity       Severity
	Path           string
	Message        string
	Recommendation string
}

// Analyzer analyzes a parsed configuration document.
type Analyzer interface {
	Analyze(context.Context, parser.Document) ([]Problem, error)
}

// Rule evaluates one category of insecure configuration.
type Rule interface {
	ID() string
	Check(context.Context, parser.Document) ([]Problem, error)
}
