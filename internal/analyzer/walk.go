package analyzer

import (
	"fmt"
	"sort"

	"cfgscan/internal/parser"
)

// Node is a value encountered while walking a configuration document.
// Key is set for values directly stored in a map.
type Node struct {
	Path  string
	Key   string
	Value any
}

// Walk visits every value in a document. Map keys are processed in lexical
// order so rules produce deterministic findings.
func Walk(document parser.Document, visit func(Node) error) error {
	return walk(document.Value, "", "", visit)
}

func walk(value any, path, key string, visit func(Node) error) error {
	if err := visit(Node{Path: path, Key: key, Value: value}); err != nil {
		return err
	}

	switch value := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, childKey := range keys {
			if err := walk(value[childKey], joinPath(path, childKey), childKey, visit); err != nil {
				return err
			}
		}
	case []any:
		for index, child := range value {
			childPath := fmt.Sprintf("[%d]", index)
			if path != "" {
				childPath = fmt.Sprintf("%s[%d]", path, index)
			}
			if err := walk(child, childPath, "", visit); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}
