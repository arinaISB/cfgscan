// Package parser converts YAML and JSON configuration data into a common tree.
package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Document is a parsed configuration tree. Value is one of map[string]any,
// []any, string, bool, numeric values, or nil.
type Document struct {
	Value any
}

// Parse reads a single JSON or YAML document.
//
// JSON is tried first, so JSON documents always use JSON number semantics. If it
// is not valid JSON, YAML parsing is attempted. An empty document is accepted as
// YAML and has a nil Value. Multiple YAML documents are not supported.
func Parse(data []byte) (Document, error) {
	document, jsonErr := parseJSON(data)
	if jsonErr == nil {
		return document, nil
	}

	document, yamlErr := parseYAML(data)
	if yamlErr == nil {
		return document, nil
	}

	return Document{}, fmt.Errorf("parse configuration: invalid JSON (%v) and invalid YAML (%w)", jsonErr, yamlErr)
}

func parseJSON(data []byte) (Document, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var value any
	if err := decoder.Decode(&value); err != nil {
		return Document{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Document{}, err
	}
	return Document{Value: value}, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("multiple JSON values are not supported")
	}
	return err
}

func parseYAML(data []byte) (Document, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		if err == io.EOF {
			return Document{Value: nil}, nil
		}
		return Document{}, err
	}

	var extra yaml.Node
	err := decoder.Decode(&extra)
	if err != io.EOF {
		if err == nil {
			return Document{}, fmt.Errorf("multiple YAML documents are not supported")
		}
		return Document{}, err
	}

	value, err := normalizeNode(&node)
	if err != nil {
		return Document{}, err
	}
	return Document{Value: value}, nil
}

func normalizeNode(node *yaml.Node) (any, error) {
	if node == nil || node.Kind == 0 {
		return nil, nil
	}
	if node.Kind == yaml.AliasNode {
		return normalizeNode(node.Alias)
	}

	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) == 0 {
			return nil, nil
		}
		return normalizeNode(node.Content[0])
	case yaml.MappingNode:
		result := make(map[string]any, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("YAML mapping key at line %d must be a scalar", key.Line)
			}
			keyText := key.Value
			if _, exists := result[keyText]; exists {
				return nil, fmt.Errorf("duplicate YAML mapping key %q", keyText)
			}
			value, err := normalizeNode(node.Content[index+1])
			if err != nil {
				return nil, err
			}
			result[keyText] = value
		}
		return result, nil
	case yaml.SequenceNode:
		result := make([]any, len(node.Content))
		for index, child := range node.Content {
			value, err := normalizeNode(child)
			if err != nil {
				return nil, err
			}
			result[index] = value
		}
		return result, nil
	case yaml.ScalarNode:
		return normalizeScalar(node)
	default:
		return nil, fmt.Errorf("unsupported YAML node at line %d", node.Line)
	}
}

func normalizeScalar(node *yaml.Node) (any, error) {
	if node.Tag == "!!null" {
		return nil, nil
	}
	if node.Tag == "!!timestamp" {
		return node.Value, nil
	}

	var value any
	if err := node.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}
