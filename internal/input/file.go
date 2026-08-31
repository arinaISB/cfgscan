package input

import (
	"fmt"
	"io"
	"os"
)

// OpenFile opens a configuration file as an input source.
// The caller must close the returned file when it is no longer needed.
func OpenFile(path string) (Source, io.Closer, error) {
	file, err := os.Open(path)
	if err != nil {
		return Source{}, nil, fmt.Errorf("open configuration file %q: %w", path, err)
	}
	return Source{Name: path, Reader: file}, file, nil
}
