package filescan

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"cfgscan/internal/analyzer"
)

func TestFilesRecursivelyFindsSupportedRegularFilesInOrder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "z.yaml"), "x: 1")
	writeFile(t, filepath.Join(dir, "skip.txt"), "x: 1")
	writeFile(t, filepath.Join(dir, "nested", "b.yml"), "x: 1")
	writeFile(t, filepath.Join(dir, "nested", "a.json"), "{}")
	writeFile(t, filepath.Join(dir, "nested", "ignored.conf"), "x: 1")
	if err := os.Symlink(filepath.Join(dir, "z.yaml"), filepath.Join(dir, "link.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nested"), filepath.Join(dir, "linked-dir")); err != nil {
		t.Fatal(err)
	}

	got, err := Files(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(dir, "nested", "a.json"),
		filepath.Join(dir, "nested", "b.yml"),
		filepath.Join(dir, "z.yaml"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Files() = %q, want %q", got, want)
	}
}

func TestFilesKeepsExplicitSingleFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	writeFile(t, path, "valid: true")
	got, err := Files(path)
	if err != nil || !reflect.DeepEqual(got, []string{path}) {
		t.Fatalf("Files() = %q, %v; want %q, nil", got, err, []string{path})
	}
}

func TestFilesRejectsExplicitSymbolicLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	link := filepath.Join(dir, "link.yaml")
	writeFile(t, target, "valid: true")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	files, err := Files(link)
	if err == nil {
		t.Fatal("Files() error = nil, want symbolic link error")
	}
	if !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), "symbolic links are not supported") {
		t.Fatalf("error = %q, want link path and symbolic link explanation", err)
	}
	if len(files) != 0 {
		t.Fatalf("Files() = %q, want no files", files)
	}
}

func TestPermissionProblem(t *testing.T) {
	tests := []struct {
		name string
		mode os.FileMode
		want analyzer.Severity
	}{
		{name: "group writable", mode: 0o620, want: analyzer.SeverityHigh},
		{name: "world writable", mode: 0o602, want: analyzer.SeverityHigh},
		{name: "group readable", mode: 0o640, want: analyzer.SeverityMedium},
		{name: "world readable", mode: 0o604, want: analyzer.SeverityMedium},
		{name: "restricted", mode: 0o600},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config.yaml")
				writeFile(t, path, "valid: true")
				if err := os.Chmod(path, test.mode); err != nil {
					t.Fatal(err)
				}
				problem, err := PermissionProblem(path)
				if err != nil {
					t.Fatal(err)
				}
				if test.want == "" {
					if problem != nil {
						t.Fatalf("problem = %#v, want nil", problem)
					}
					return
				}
				if problem == nil || problem.Severity != test.want || problem.RuleID != "insecure-file-permissions" || problem.Source != path {
					t.Fatalf("problem = %#v", problem)
				}
			},
		)
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
