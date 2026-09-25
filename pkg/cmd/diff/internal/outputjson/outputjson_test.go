package outputjson_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/outputjson"
)

func TestWrite(t *testing.T) {
	tests := []struct {
		name     string
		stale    bool   // a file from a previous run exists at path beforehand
		summary  string // "" means the diff failed before producing a summary
		wantFile bool
		want     string
	}{
		{name: "writes summary", summary: `{"pass":true}`, wantFile: true, want: `{"pass":true}`},
		{name: "replaces previous summary", stale: true, summary: `{"pass":false}`, wantFile: true, want: `{"pass":false}`},
		{name: "no summary leaves no file", summary: "", wantFile: false},
		{name: "no summary removes stale file from a previous run", stale: true, summary: "", wantFile: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "diff.json")
			if tt.stale {
				if err := os.WriteFile(path, []byte(`{"stale":true}`), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			if err := outputjson.Write(path, []byte(tt.summary)); err != nil {
				t.Fatalf("Write() error = %v", err)
			}

			got, err := os.ReadFile(path)
			switch {
			case !tt.wantFile:
				if err == nil {
					t.Fatalf("Write() left a file at %s with content %q, want none", path, got)
				}
				if !os.IsNotExist(err) {
					t.Fatal(err)
				}
			case err != nil:
				t.Fatalf("Write() produced no readable file: %v", err)
			case string(got) != tt.want:
				t.Errorf("Write() content = %q, want %q", got, tt.want)
			}

			// No temporary file may survive next to the destination.
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.Name() != filepath.Base(path) {
					t.Errorf("unexpected leftover %s", e.Name())
				}
			}
		})
	}

	t.Run("empty path is a no-op", func(t *testing.T) {
		if err := outputjson.Write("", []byte(`{"pass":true}`)); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	})
}

func TestClear(t *testing.T) {
	t.Run("removes stale file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "diff.json")
		if err := os.WriteFile(path, []byte(`{"stale":true}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := outputjson.Clear(path); err != nil {
			t.Fatalf("Clear() error = %v", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("Clear() left %s behind (stat err = %v)", path, err)
		}
	})
	t.Run("missing file is fine", func(t *testing.T) {
		if err := outputjson.Clear(filepath.Join(t.TempDir(), "diff.json")); err != nil {
			t.Fatalf("Clear() error = %v", err)
		}
	})
	t.Run("empty path is a no-op", func(t *testing.T) {
		if err := outputjson.Clear(""); err != nil {
			t.Fatalf("Clear() error = %v", err)
		}
	})
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	baseline := mk("baseline.db")
	target := mk("target.db")
	scanDir := filepath.Join(dir, "scan-results")
	if err := os.Mkdir(scanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mk("scan-results/rhel_10.json")
	link := filepath.Join(dir, "alias.db")
	if err := os.Symlink(baseline, link); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(dir, "scan-alias")
	if err := os.Symlink(scanDir, dirLink); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		inputs  []string
		wantErr bool
	}{
		{name: "empty path", path: "", inputs: []string{baseline}},
		{name: "unrelated new file", path: filepath.Join(dir, "diff.json"), inputs: []string{baseline, target, scanDir}},
		{name: "same file", path: baseline, inputs: []string{baseline, target}, wantErr: true},
		{name: "symlink alias of an input", path: link, inputs: []string{baseline}, wantErr: true},
		{name: "input given through a symlink", path: baseline, inputs: []string{link}, wantErr: true},
		{name: "file inside input directory", path: filepath.Join(scanDir, "rhel_10.json"), inputs: []string{scanDir}, wantErr: true},
		{name: "new file inside input directory", path: filepath.Join(scanDir, "diff.json"), inputs: []string{scanDir}, wantErr: true},
		{name: "new file inside symlinked input directory", path: filepath.Join(dirLink, "diff.json"), inputs: []string{scanDir}, wantErr: true},
		{name: "sibling with the directory name as prefix", path: filepath.Join(dir, "scan-results.json"), inputs: []string{scanDir}},
		{name: "nonexistent input is ignored", path: filepath.Join(dir, "diff.json"), inputs: []string{filepath.Join(dir, "missing.db")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := outputjson.Validate(tt.path, tt.inputs...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
