package validate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestValidate(t *testing.T) {
	type args struct {
		root string
		opts []Option
	}
	tests := []struct {
		name    string
		args    args
		want    []Finding
		wantErr bool
	}{
		{
			name: "clean",
			args: args{root: "./testdata/fixtures/clean"},
		},
		{
			name: "broken",
			args: args{root: "./testdata/fixtures/broken"},
			want: []Finding{
				{
					Path:    "data/2024/CVE-2024-0002.json",
					Line:    22,
					ID:      "CVE-2024-0002",
					Rule:    "cpe-pvp",
					Message: `detection cpe: condition "vulnerable": criterion cpe "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*" and cpe_match "cpe:2.3:a:vendor:other:1.0.0:*:*:*:*:*:*:*" disagree on product: "product" != "other"`,
				},
				{
					Path:    "data/2024/CVE-2024-0002.json",
					Line:    6,
					ID:      "CVE-2024-0002",
					Rule:    "orphan-segment",
					Message: "advisory ADV-2024-0002: segment (ecosystem: cpe, tag: orphan) has no corresponding detection condition",
				},
			},
		},
		{
			name: "selected rule only",
			args: args{root: "./testdata/fixtures/broken", opts: []Option{WithRules([]string{"orphan-segment"})}},
			want: []Finding{
				{
					Path:    "data/2024/CVE-2024-0002.json",
					Line:    6,
					ID:      "CVE-2024-0002",
					Rule:    "orphan-segment",
					Message: "advisory ADV-2024-0002: segment (ecosystem: cpe, tag: orphan) has no corresponding detection condition",
				},
			},
		},
		{
			name: "duplicate rule names are deduplicated",
			args: args{root: "./testdata/fixtures/broken", opts: []Option{WithRules([]string{"orphan-segment", "orphan-segment"})}},
			want: []Finding{
				{
					Path:    "data/2024/CVE-2024-0002.json",
					Line:    6,
					ID:      "CVE-2024-0002",
					Rule:    "orphan-segment",
					Message: "advisory ADV-2024-0002: segment (ecosystem: cpe, tag: orphan) has no corresponding detection condition",
				},
			},
		},
		{
			name:    "unknown rule",
			args:    args{root: "./testdata/fixtures/clean", opts: []Option{WithRules([]string{"no-such-rule"})}},
			wantErr: true,
		},
		{
			name: "no content directory",
			args: args{root: "./testdata/fixtures/no-content"},
			want: []Finding{
				{Path: ".", Rule: "layout", Message: "no content directory (expected at least one of: attack, capec, cwe, data, eol, microsoftkb)"},
				{Path: "datasource.json", Rule: "layout", Message: "datasource.json is missing"},
			},
		},
		{
			name: "data is not a directory",
			args: args{root: "./testdata/fixtures/data-is-file"},
			want: []Finding{
				{Path: ".", Rule: "layout", Message: "no content directory (expected at least one of: attack, capec, cwe, data, eol, microsoftkb)"},
				{Path: "data", Rule: "layout", Message: "data is not a directory"},
				{Path: "datasource.json", Rule: "layout", Message: "datasource.json is missing"},
			},
		},
		{
			name:    "root does not exist",
			args:    args{root: "./testdata/fixtures/no-such-dir"},
			wantErr: true,
		},
		{
			name:    "root is not a directory",
			args:    args{root: "./testdata/fixtures/clean/datasource.json"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Validate(tt.args.root, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Validate() (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestInspectLayout(t *testing.T) {
	// Built at runtime: a directory literally named .git cannot be committed
	// as a fixture.
	root := t.TempDir()
	for _, d := range []string{"data", "microsoftkb", ".git", "unknown-dir"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"datasource.json", "README.md"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	findings, err := inspectLayout(root)
	if err != nil {
		t.Fatalf("inspectLayout() error = %v", err)
	}
	// data + microsoftkb coexisting is legitimate (microsoft-bulletin/cvrf);
	// only the unknown entry must be reported.
	want := []Finding{
		{Path: "unknown-dir", Rule: "layout", Message: `unknown top-level entry (expected: ["attack" "capec" "cwe" "data" "eol" "microsoftkb" ".git" "README.md" "datasource.json"])`},
	}
	if diff := cmp.Diff(want, findings); diff != "" {
		t.Errorf("inspectLayout() (-expected +got):\n%s", diff)
	}
}
