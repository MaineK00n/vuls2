package thresholdflag_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/pflag"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/thresholdflag"
	"github.com/MaineK00n/vuls2/pkg/diff/threshold"
)

func TestThreshold(t *testing.T) {
	// The commands' built-in defaults, as pkg/diff/db and pkg/diff/detection
	// declare them.
	allDefaults := threshold.Rates{threshold.Added: 30, threshold.Changed: 10, threshold.Removed: 10}
	twoDefaults := threshold.Rates{threshold.Added: 30, threshold.Removed: 5}
	tests := []struct {
		name    string
		axes    []threshold.Axis
		argv    []string
		want    threshold.Threshold
		wantErr bool
	}{
		{
			// No flag at all: the command's built-in defaults.
			name: "defaults",
			axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv: nil,
			want: threshold.Threshold{Axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, Default: allDefaults},
		},
		{
			// Named axes replace their built-in default; added keeps 30.
			name: "per-axis flags",
			axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv: []string{
				"--rate-threshold", "changed:5", "--rate-threshold", "removed:0",
				"--rate-threshold-override", "ubuntu:26.04=added:80",
				"--rate-threshold-override", "cpe/cisco-json=removed:25,microsoft/microsoft-msuc=added:35",
			},
			want: threshold.Threshold{
				Axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
				Default: threshold.Rates{threshold.Added: 30, threshold.Changed: 5, threshold.Removed: 0},
				Overrides: map[string]threshold.Rates{
					"ubuntu:26.04":             {threshold.Added: 80},
					"microsoft/microsoft-msuc": {threshold.Added: 35},
					"cpe/cisco-json":           {threshold.Removed: 25},
				},
			},
		},
		{
			name: "comma-separated entries",
			axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv: []string{"--rate-threshold", "added:50,changed:10,removed:5"},
			want: threshold.Threshold{
				Axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
				Default: threshold.Rates{threshold.Added: 50, threshold.Changed: 10, threshold.Removed: 5},
			},
		},
		{
			// Only the declared axes are accepted.
			name:    "changed axis rejected on a two-axis command",
			axes:    []threshold.Axis{threshold.Added, threshold.Removed},
			argv:    []string{"--rate-threshold", "changed:10"},
			wantErr: true,
		},
		{
			name:    "override form rejected in --rate-threshold",
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv:    []string{"--rate-threshold", "ubuntu:26.04=added:50"},
			wantErr: true,
		},
		{
			name:    "bare rate rejected in --rate-threshold",
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv:    []string{"--rate-threshold", "10"},
			wantErr: true,
		},
		{
			// An empty value means "no entries": every axis keeps its
			// built-in default.
			name: "empty --rate-threshold keeps defaults",
			axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv: []string{"--rate-threshold", ""},
			want: threshold.Threshold{Axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, Default: allDefaults},
		},
		{
			name: "two-axis defaults",
			axes: []threshold.Axis{threshold.Added, threshold.Removed},
			argv: nil,
			want: threshold.Threshold{Axes: []threshold.Axis{threshold.Added, threshold.Removed}, Default: twoDefaults},
		},
		{
			name: "two-axis flag overrides a default",
			axes: []threshold.Axis{threshold.Added, threshold.Removed},
			argv: []string{"--rate-threshold", "removed:1"},
			want: threshold.Threshold{
				Axes:    []threshold.Axis{threshold.Added, threshold.Removed},
				Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 1},
			},
		},
		{
			// Legacy flags map onto every axis, overriding the built-in
			// added default too — the pre-axis judgement is reproduced.
			name: "legacy flags map onto every axis",
			axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv: []string{"--change-rate-threshold", "10", "--change-rate-threshold-override", "ubuntu:26.04=30,cpe/cisco-json=25"},
			want: threshold.Threshold{
				Axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
				Default: threshold.Rates{threshold.Added: 10, threshold.Changed: 10, threshold.Removed: 10},
				Overrides: map[string]threshold.Rates{
					"ubuntu:26.04":   {threshold.Added: 30, threshold.Changed: 30, threshold.Removed: 30},
					"cpe/cisco-json": {threshold.Added: 25, threshold.Changed: 25, threshold.Removed: 25},
				},
			},
		},
		{
			name: "legacy override alone",
			axes: []threshold.Axis{threshold.Added, threshold.Removed},
			argv: []string{"--change-rate-threshold-override", "debian_13=15"},
			want: threshold.Threshold{
				Axes:    []threshold.Axis{threshold.Added, threshold.Removed},
				Default: threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
				Overrides: map[string]threshold.Rates{
					"debian_13": {threshold.Added: 15, threshold.Removed: 15},
				},
			},
		},
		{
			name:    "legacy threshold with per-axis threshold",
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv:    []string{"--change-rate-threshold", "10", "--rate-threshold", "removed:10"},
			wantErr: true,
		},
		{
			name:    "legacy override with per-axis override",
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv:    []string{"--change-rate-threshold-override", "cpe=25", "--rate-threshold-override", "cpe=added:25"},
			wantErr: true,
		},
		{
			// Appearing counts as used even when the value is empty.
			name:    "empty legacy override with per-axis threshold",
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv:    []string{"--change-rate-threshold-override", "", "--rate-threshold", "removed:10"},
			wantErr: true,
		},
		{
			// An empty per-axis override list is the no-overrides default,
			// as the CI caller passes it verbatim.
			name: "empty per-axis override list",
			axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv: []string{"--rate-threshold-override", ""},
			want: threshold.Threshold{Axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, Default: allDefaults},
		},
		{
			name:    "malformed per-axis override",
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv:    []string{"--rate-threshold-override", "cpe=25"},
			wantErr: true,
		},
		{
			name:    "malformed legacy override",
			axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			argv:    []string{"--change-rate-threshold-override", "cpe"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			defaults := allDefaults
			if len(tt.axes) == 2 {
				defaults = twoDefaults
			}
			f := thresholdflag.Register(fs, tt.axes, defaults, "(target)", "<key>")
			if err := fs.Parse(tt.argv); err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("Parse() error = %v", err)
			}
			got, err := f.Threshold(fs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Threshold() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Threshold() mismatch (-want +got):\n%s", diff)
			}
			if err := got.Validate(); err != nil {
				t.Errorf("Threshold() produced an invalid threshold: %v", err)
			}
		})
	}
}
