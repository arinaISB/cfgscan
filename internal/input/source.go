// Package input defines configuration input sources.
package input

import "io"

// Source is configuration data supplied to the application.
// New source types, such as HTTP or gRPC requests, can construct this value.
type Source struct {
	Name   string
	Reader io.Reader
}
