// Package app orchestrates configuration analysis independently of any transport.
package app

import (
	"context"
	"fmt"
	"io"

	"cfgscan/internal/analyzer"
	"cfgscan/internal/parser"
)

// Service runs analysis using a supplied Analyzer.
type Service struct {
	analyzer analyzer.Analyzer
}

func New(a analyzer.Analyzer) Service {
	return Service{analyzer: a}
}

// Analyze reads, parses, and analyzes one configuration document.
func (s Service) Analyze(ctx context.Context, input io.Reader) ([]analyzer.Problem, error) {
	if s.analyzer == nil {
		return nil, fmt.Errorf("analyzer is not configured")
	}

	data, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	document, err := parser.Parse(data)
	if err != nil {
		return nil, err
	}
	return s.analyzer.Analyze(ctx, document)
}
