package override_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/override"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		want    map[string]float64
		wantErr bool
	}{
		{
			name:    "nil entries",
			entries: nil,
			want:    nil,
		},
		{
			name:    "empty slice",
			entries: []string{},
			want:    nil,
		},
		{
			name:    "single entry",
			entries: []string{"ubuntu:26.04=25"},
			want:    map[string]float64{"ubuntu:26.04": 25},
		},
		{
			name:    "multiple entries",
			entries: []string{"ubuntu:26.04=25", "debian_13=8", "redhat:9=12.5"},
			want: map[string]float64{
				"ubuntu:26.04": 25,
				"debian_13":    8,
				"redhat:9":     12.5,
			},
		},
		{
			name:    "whitespace tolerated",
			entries: []string{"  ubuntu:26.04 = 25 ", "\tdebian_13=8\t"},
			want: map[string]float64{
				"ubuntu:26.04": 25,
				"debian_13":    8,
			},
		},
		{
			// Locks the slash-qualified key syntax: keys are opaque to Parse,
			// so <ecosystem>/<source> (diff db) and <file>/<family> (diff
			// detection) pass through unchanged.
			name:    "slash-qualified keys pass through",
			entries: []string{"cpe/cisco-json=30", "cpe_jvn/Jvn=25"},
			want: map[string]float64{
				"cpe/cisco-json": 30,
				"cpe_jvn/Jvn":    25,
			},
		},
		{
			name:    "explicit zero kept",
			entries: []string{"strict-target=0"},
			want:    map[string]float64{"strict-target": 0},
		},
		{
			name:    "duplicate key last wins",
			entries: []string{"ubuntu:26.04=10", "ubuntu:26.04=25"},
			want:    map[string]float64{"ubuntu:26.04": 25},
		},
		{
			name:    "rate over 100 allowed",
			entries: []string{"new-distro=150"},
			want:    map[string]float64{"new-distro": 150},
		},
		{
			name:    "missing separator",
			entries: []string{"ubuntu:26.04"},
			wantErr: true,
		},
		{
			name:    "empty key",
			entries: []string{"=25"},
			wantErr: true,
		},
		{
			name:    "non-numeric rate",
			entries: []string{"ubuntu:26.04=abc"},
			wantErr: true,
		},
		{
			name:    "negative rate",
			entries: []string{"ubuntu:26.04=-5"},
			wantErr: true,
		},
		{
			name:    "NaN rate",
			entries: []string{"ubuntu:26.04=NaN"},
			wantErr: true,
		},
		{
			name:    "+Inf rate",
			entries: []string{"ubuntu:26.04=+Inf"},
			wantErr: true,
		},
		{
			name:    "-Inf rate",
			entries: []string{"ubuntu:26.04=-Inf"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := override.Parse(tt.entries)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Parse() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
