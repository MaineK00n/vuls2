package push

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseAnnotations(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    map[string]string
		wantErr bool
	}{
		{
			name: "empty",
			args: nil,
			want: nil,
		},
		{
			name: "single",
			args: []string{"io.vuls.db.branch=nightly"},
			want: map[string]string{"io.vuls.db.branch": "nightly"},
		},
		{
			name: "multiple, value containing =",
			args: []string{
				"io.vuls.db.branch=main",
				"io.vuls.db.build.run-url=https://github.com/vulsio/vuls-data-db/actions/runs/1?check_suite_focus=true",
			},
			want: map[string]string{
				"io.vuls.db.branch":        "main",
				"io.vuls.db.build.run-url": "https://github.com/vulsio/vuls-data-db/actions/runs/1?check_suite_focus=true",
			},
		},
		{
			name: "empty value",
			args: []string{"io.vuls.db.branch="},
			want: map[string]string{"io.vuls.db.branch": ""},
		},
		{
			name:    "missing =",
			args:    []string{"io.vuls.db.branch"},
			wantErr: true,
		},
		{
			name:    "empty key",
			args:    []string{"=nightly"},
			wantErr: true,
		},
		{
			name:    "duplicate key",
			args:    []string{"io.vuls.db.branch=main", "io.vuls.db.branch=nightly"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAnnotations(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAnnotations() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("parseAnnotations() mismatch (-got +want):\n%s", diff)
			}
		})
	}
}
