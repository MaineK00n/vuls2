package validate_test

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls2/pkg/validate"
)

func TestValidate(t *testing.T) {
	type args struct {
		root string
		opts []validate.Option
	}
	tests := []struct {
		name    string
		args    args
		want    []validate.Finding
		wantErr bool
	}{
		{
			name: "clean",
			args: args{root: "./testdata/fixtures/clean"},
		},
		{
			name: "broken",
			args: args{root: "./testdata/fixtures/broken"},
			want: []validate.Finding{
				{
					Path:    "data/2024/CVE-2024-0002.json",
					Line:    22,
					RootID:  "CVE-2024-0002",
					Rule:    "cpe-pvp",
					Message: `detection cpe: condition "vulnerable": criterion cpe "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*" and cpe_match "cpe:2.3:a:vendor:other:1.0.0:*:*:*:*:*:*:*" disagree on product: "product" != "other"`,
				},
				{
					Path:    "data/2024/CVE-2024-0002.json",
					Line:    6,
					RootID:  "CVE-2024-0002",
					Rule:    "orphan-segment",
					Message: "advisory ADV-2024-0002: segment (ecosystem: cpe, tag: orphan) has no corresponding detection condition",
				},
			},
		},
		{
			name: "selected rule only",
			args: args{root: "./testdata/fixtures/broken", opts: []validate.Option{validate.WithRules([]string{"orphan-segment"})}},
			want: []validate.Finding{
				{
					Path:    "data/2024/CVE-2024-0002.json",
					Line:    6,
					RootID:  "CVE-2024-0002",
					Rule:    "orphan-segment",
					Message: "advisory ADV-2024-0002: segment (ecosystem: cpe, tag: orphan) has no corresponding detection condition",
				},
			},
		},
		{
			name: "duplicate rule names are deduplicated",
			args: args{root: "./testdata/fixtures/broken", opts: []validate.Option{validate.WithRules([]string{"orphan-segment", "orphan-segment"})}},
			want: []validate.Finding{
				{
					Path:    "data/2024/CVE-2024-0002.json",
					Line:    6,
					RootID:  "CVE-2024-0002",
					Rule:    "orphan-segment",
					Message: "advisory ADV-2024-0002: segment (ecosystem: cpe, tag: orphan) has no corresponding detection condition",
				},
			},
		},
		{
			name:    "unknown rule",
			args:    args{root: "./testdata/fixtures/clean", opts: []validate.Option{validate.WithRules([]string{"no-such-rule"})}},
			wantErr: true,
		},
		{
			name: "no content directory",
			args: args{root: "./testdata/fixtures/no-content"},
			want: []validate.Finding{
				{Path: ".", Rule: "layout", Message: "no content directory (expected at least one of: attack, capec, cwe, data, eol, microsoftkb)"},
				{Path: "datasource.json", Rule: "layout", Message: "datasource.json is missing"},
			},
		},
		{
			name:    "data is not a directory",
			args:    args{root: "./testdata/fixtures/data-is-file"},
			wantErr: true,
		},
		{
			name: "data is not a directory with layout rule only",
			args: args{root: "./testdata/fixtures/data-is-file", opts: []validate.Option{validate.WithRules([]string{"layout"})}},
			want: []validate.Finding{
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
			got, err := validate.Validate(tt.args.root, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			slices.SortFunc(got, validate.Finding.Compare)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Validate() (-expected +got):\n%s", diff)
			}
		})
	}
}
