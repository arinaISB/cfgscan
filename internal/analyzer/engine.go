package analyzer

import (
	"context"
	"fmt"
	"sort"

	"cfgscan/internal/parser"
)

// Engine runs a collection of independent security rules.
type Engine struct {
	rules []Rule
}

// NewEngine creates an analyzer with the supplied rules.
func NewEngine(rules ...Rule) Engine {
	return Engine{rules: rules}
}

func (e Engine) Analyze(ctx context.Context, document parser.Document) ([]Problem, error) {
	problems := make([]Problem, 0)
	for _, rule := range e.rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if rule == nil {
			return nil, fmt.Errorf("analyzer has a nil rule")
		}

		findings, err := rule.Check(ctx, document)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.ID(), err)
		}
		for index := range findings {
			findings[index].RuleID = rule.ID()
		}
		problems = append(problems, findings...)
	}

	sort.Slice(problems, func(i, j int) bool {
		if problems[i].Path != problems[j].Path {
			return problems[i].Path < problems[j].Path
		}
		return problems[i].RuleID < problems[j].RuleID
	})
	return problems, nil
}
