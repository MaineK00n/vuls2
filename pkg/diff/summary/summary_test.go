package summary_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls2/pkg/diff/summary"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name  string
		check summary.Check
		pass  bool
		rows  []summary.Row
		want  summary.Summary
	}{
		{
			name:  "nil rows become an empty array",
			check: summary.CheckDB,
			pass:  true,
			rows:  nil,
			want:  summary.Summary{SchemaVersion: 1, Check: summary.CheckDB, Pass: true, Rows: []summary.Row{}},
		},
		{
			name:  "rows sorted by name then source",
			check: summary.CheckDetection,
			pass:  false,
			rows: []summary.Row{
				{Name: "ubuntu_2204", Source: "ubuntu-oval", ChangeRate: 66.7, Threshold: 5, Pass: false},
				{Name: "cpe_nvd", Source: "vulncheck-nist-nvd2", ChangeRate: 8.7, Threshold: 5, Pass: false},
				{Name: "cpe_nvd", Source: "nvd-feed-cve-v2", ChangeRate: 0, Threshold: 5, Pass: true},
			},
			want: summary.Summary{SchemaVersion: 1, Check: summary.CheckDetection, Pass: false, Rows: []summary.Row{
				{Name: "cpe_nvd", Source: "nvd-feed-cve-v2", ChangeRate: 0, Threshold: 5, Pass: true},
				{Name: "cpe_nvd", Source: "vulncheck-nist-nvd2", ChangeRate: 8.7, Threshold: 5, Pass: false},
				{Name: "ubuntu_2204", Source: "ubuntu-oval", ChangeRate: 66.7, Threshold: 5, Pass: false},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := append([]summary.Row(nil), tt.rows...)
			got := summary.New(tt.check, tt.pass, tt.rows)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("New() mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(in, tt.rows); diff != "" {
				t.Errorf("New() mutated its input (-before +after):\n%s", diff)
			}
		})
	}
}

// TestWrite pins the exact bytes of the contract. vuls-data-db's diff-guard
// consumes this file and may lag behind vuls2 by weeks, so any change to the
// key set, key names, value types, or formatting must show up here as a
// deliberate golden update (and, for removals/renames/retypes, a
// SchemaVersion bump).
func TestWrite(t *testing.T) {
	tests := []struct {
		name string
		in   summary.Summary
		want string
	}{
		{
			name: "rows",
			in: summary.New(summary.CheckDB, false, []summary.Row{
				{Name: "redhat:10", Source: "redhat-vex", ChangeRate: 6.5, Threshold: 5, Pass: false},
				{Name: "alma:8", Source: "alma-errata", ChangeRate: 0, Threshold: 10, Pass: true},
			}),
			want: `{
  "schema_version": 1,
  "check": "db",
  "pass": false,
  "rows": [
    {
      "name": "alma:8",
      "source": "alma-errata",
      "change_rate": 0,
      "threshold": 10,
      "pass": true
    },
    {
      "name": "redhat:10",
      "source": "redhat-vex",
      "change_rate": 6.5,
      "threshold": 5,
      "pass": false
    }
  ]
}
`,
		},
		{
			name: "no rows",
			in:   summary.New(summary.CheckDetection, true, nil),
			want: `{
  "schema_version": 1,
  "check": "detection",
  "pass": true,
  "rows": []
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tt.in.Write(&buf); err != nil {
				t.Fatalf("Write() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, buf.String()); diff != "" {
				t.Errorf("Write() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
