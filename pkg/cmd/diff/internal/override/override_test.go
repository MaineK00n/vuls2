package override_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/override"
	"github.com/MaineK00n/vuls2/pkg/diff/threshold"
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
			// so <ecosystem>/<source> (diff db) and <file>/<source> (diff
			// detection) pass through unchanged.
			name:    "slash-qualified keys pass through",
			entries: []string{"cpe/cisco-json=30", "cpe_jvn/jvn-feed-rss=25"},
			want: map[string]float64{
				"cpe/cisco-json":       30,
				"cpe_jvn/jvn-feed-rss": 25,
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

func TestParseAxes(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		axes    []threshold.Axis
		want    map[string]threshold.Rates
		wantErr bool
	}{
		{
			name:    "nil entries",
			entries: nil,
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			want:    nil,
		},
		{
			name:    "single entry",
			entries: []string{"ubuntu:26.04=added:50"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			want:    map[string]threshold.Rates{"ubuntu:26.04": {threshold.Added: 50}},
		},
		{
			// Keys containing ":" and "/" are split only at the first "=",
			// so the axis separator inside the value is unambiguous.
			name:    "keys with colon and slash, several axes",
			entries: []string{"ubuntu:26.04=added:50", "cpe/cisco-json=removed:20", "cpe/cisco-json=changed:15"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			want: map[string]threshold.Rates{
				"ubuntu:26.04":   {threshold.Added: 50},
				"cpe/cisco-json": {threshold.Changed: 15, threshold.Removed: 20},
			},
		},
		{
			name:    "whitespace tolerated",
			entries: []string{"  debian_13 = added : 15 "},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			want:    map[string]threshold.Rates{"debian_13": {threshold.Added: 15}},
		},
		{
			name:    "duplicate key and axis last wins",
			entries: []string{"debian_13=added:10", "debian_13=added:25"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			want:    map[string]threshold.Rates{"debian_13": {threshold.Added: 25}},
		},
		{
			name:    "explicit zero kept",
			entries: []string{"strict=removed:0"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			want:    map[string]threshold.Rates{"strict": {threshold.Removed: 0}},
		},
		{
			// The legacy "<key>=<rate>" form is refused: an override must
			// name the axis it relaxes.
			name:    "missing axis",
			entries: []string{"debian_13=15"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			wantErr: true,
		},
		{
			name:    "missing separator",
			entries: []string{"debian_13"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			wantErr: true,
		},
		{
			name:    "empty key",
			entries: []string{"=added:15"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			wantErr: true,
		},
		{
			name:    "empty axis",
			entries: []string{"debian_13=:15"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			wantErr: true,
		},
		{
			name:    "unknown axis",
			entries: []string{"debian_13=deleted:15"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			wantErr: true,
		},
		{
			name:    "axis is case-sensitive",
			entries: []string{"debian_13=Added:15"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			wantErr: true,
		},
		{
			// detection judges only added and removed.
			name:    "axis not judged by this command",
			entries: []string{"debian_13=changed:15"},
			axes:    []threshold.Axis{threshold.Added, threshold.Removed},
			wantErr: true,
		},
		{
			name:    "non-numeric rate",
			entries: []string{"debian_13=added:abc"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			wantErr: true,
		},
		{
			name:    "negative rate",
			entries: []string{"debian_13=added:-5"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			wantErr: true,
		},
		{
			name:    "NaN rate",
			entries: []string{"debian_13=added:NaN"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			wantErr: true,
		},
		{
			name:    "Inf rate",
			entries: []string{"debian_13=added:Inf"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := override.ParseAxes(tt.entries, tt.axes)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseAxes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseAxes() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseDefaults(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		axes    []threshold.Axis
		want    threshold.Rates
		wantErr bool
	}{
		{name: "nil entries", entries: nil, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, want: nil},
		{name: "single axis", entries: []string{"removed:5"}, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, want: threshold.Rates{threshold.Removed: 5}},
		{
			name:    "every axis",
			entries: []string{"added:50", "changed:10", "removed:5"},
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			want:    threshold.Rates{threshold.Added: 50, threshold.Changed: 10, threshold.Removed: 5},
		},
		{name: "whitespace tolerated", entries: []string{" removed : 5 "}, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, want: threshold.Rates{threshold.Removed: 5}},
		{name: "duplicate axis last wins", entries: []string{"removed:5", "removed:1"}, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, want: threshold.Rates{threshold.Removed: 1}},
		{name: "explicit zero kept", entries: []string{"removed:0"}, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, want: threshold.Rates{threshold.Removed: 0}},
		{name: "missing separator", entries: []string{"removed"}, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, wantErr: true},
		{name: "bare rate", entries: []string{"10"}, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, wantErr: true},
		{name: "override form refused", entries: []string{"debian_13=added:50"}, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, wantErr: true},
		{name: "empty axis", entries: []string{":5"}, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, wantErr: true},
		{name: "unknown axis", entries: []string{"deleted:5"}, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, wantErr: true},
		{name: "axis not judged by this command", entries: []string{"changed:5"}, axes: []threshold.Axis{threshold.Added, threshold.Removed}, wantErr: true},
		{name: "non-numeric rate", entries: []string{"removed:abc"}, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, wantErr: true},
		{name: "negative rate", entries: []string{"removed:-5"}, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, wantErr: true},
		{name: "NaN rate", entries: []string{"removed:NaN"}, axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := override.ParseDefaults(tt.entries, tt.axes)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseDefaults() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseDefaults() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
