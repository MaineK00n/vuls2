package validate_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls2/pkg/validate"
)

func TestInspectLayout(t *testing.T) {
	// Roots are built at runtime: a directory literally named .git cannot be
	// committed as a fixture.
	tests := []struct {
		name  string
		dirs  []string
		files []string
		want  []validate.Finding
	}{
		{
			name:  "ok",
			dirs:  []string{"data", "microsoftkb", ".git"},
			files: []string{"datasource.json", "README.md"},
			// data + microsoftkb coexisting is legitimate
			// (microsoft-bulletin/cvrf emit both).
		},
		{
			name:  "unknown top-level entry",
			dirs:  []string{"data", "unknown-dir"},
			files: []string{"datasource.json"},
			want: []validate.Finding{
				{Path: "unknown-dir", Rule: "layout", Message: `unknown top-level entry (expected: ["attack" "capec" "cwe" "data" "eol" "microsoftkb" ".git" "README.md" "datasource.json"])`},
			},
		},
		{
			name: "missing datasource.json",
			dirs: []string{"data"},
			want: []validate.Finding{
				{Path: "datasource.json", Rule: "layout", Message: "datasource.json is missing"},
			},
		},
		{
			name:  "no content directory",
			files: []string{"datasource.json", "README.md"},
			want: []validate.Finding{
				{Path: ".", Rule: "layout", Message: "no content directory (expected at least one of: attack, capec, cwe, data, eol, microsoftkb)"},
			},
		},
		{
			name:  "content name is not a directory",
			files: []string{"data", "datasource.json"},
			want: []validate.Finding{
				{Path: "data", Rule: "layout", Message: "data is not a directory"},
				{Path: ".", Rule: "layout", Message: "no content directory (expected at least one of: attack, capec, cwe, data, eol, microsoftkb)"},
			},
		},
		{
			name: "datasource.json is not a regular file",
			dirs: []string{"data", "datasource.json"},
			want: []validate.Finding{
				{Path: "datasource.json", Rule: "layout", Message: "datasource.json is not a regular file"},
			},
		},
		{
			name:  "README.md is not a regular file",
			dirs:  []string{"data", "README.md"},
			files: []string{"datasource.json"},
			want: []validate.Finding{
				{Path: "README.md", Rule: "layout", Message: "README.md is not a regular file"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for _, d := range tt.dirs {
				if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for _, f := range tt.files {
				if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			got, err := validate.InspectLayout(root)
			if err != nil {
				t.Fatalf("validate.InspectLayout() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("InspectLayout() (-expected +got):\n%s", diff)
			}
		})
	}
}
