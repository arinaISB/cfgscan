// Package filescan discovers configuration files and evaluates file metadata.
package filescan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cfgscan/internal/analyzer"
)

// Files returns one explicit file, or supported regular files below a directory.
// Directory symlinks and file symlinks are never followed or returned.
func Files(path string) ([]string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat configuration path %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("configuration path %q is a symbolic link; symbolic links are not supported", path)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}

	var files []string
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !entry.Type().IsRegular() || !supported(current) {
			return nil
		}
		files = append(files, current)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk configuration directory %q: %w", path, err)
	}
	sort.Strings(files)
	return files, nil
}

func supported(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".yaml", ".yml":
		return true
	default:
		return false
	}
}

// PermissionProblem returns a finding when group or world access is broader
// than the restricted permissions recommended for configuration files.
func PermissionProblem(path string) (*analyzer.Problem, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat configuration file %q: %w", path, err)
	}
	mode := info.Mode().Perm()
	problem := analyzer.Problem{
		Source:         path,
		RuleID:         "insecure-file-permissions",
		Path:           "permissions",
		Message:        "configuration file is readable by group or other users",
		Recommendation: "Restrict this configuration file to the minimum necessary permissions, for example 0600.",
		Severity:       analyzer.SeverityMedium,
	}
	if mode&0o022 != 0 {
		problem.Severity = analyzer.SeverityHigh
		problem.Message = "configuration file is writable by group or other users"
		return &problem, nil
	}
	if mode&0o044 != 0 {
		return &problem, nil
	}
	return nil, nil
}
