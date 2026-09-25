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
