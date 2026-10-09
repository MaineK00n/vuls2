package threshold_test

import (
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls2/pkg/diff/threshold"
)

var all = []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}

func TestLegacy(t *testing.T) {
	tests := []struct {
		name      string
		axes      []threshold.Axis
		def       float64
		overrides map[string]float64
		want      threshold.Config
	}{
		{
			name: "default on every axis, no overrides",
			axes: all,
			def:  10,
			want: threshold.Config{
				Axes:      all,
				Default:   threshold.Rates{threshold.Added: 10, threshold.Changed: 10, threshold.Removed: 10},
				Overrides: map[threshold.Axis]map[string]float64{},
			},
		},
		{
			name:      "overrides copied onto every axis",
			axes:      []threshold.Axis{threshold.Added, threshold.Removed},
			def:       5,
			overrides: map[string]float64{"debian_13": 15, "cpe_jvn/jvn-feed-rss": 25},
			want: threshold.Config{
				Axes:    []threshold.Axis{threshold.Added, threshold.Removed},
				Default: threshold.Rates{threshold.Added: 5, threshold.Removed: 5},
				Overrides: map[threshold.Axis]map[string]float64{
					threshold.Added:   {"debian_13": 15, "cpe_jvn/jvn-feed-rss": 25},
					threshold.Removed: {"debian_13": 15, "cpe_jvn/jvn-feed-rss": 25},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := threshold.Legacy(tt.axes, tt.def, tt.overrides)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Legacy() mismatch (-want +got):\n%s", diff)
			}
			// The per-axis maps must be independent copies: mutating one
			// axis' overrides must not leak into another.
			if len(tt.overrides) > 0 {
				got.Overrides[tt.axes[0]]["mutated"] = 1
				if _, leaked := got.Overrides[tt.axes[1]]["mutated"]; leaked {
					t.Error("Legacy() shares one override map between axes")
				}
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     threshold.Config
		wantErr bool
	}{
		{
			name: "valid",
			cfg: threshold.Config{
				Axes:      all,
				Default:   threshold.Rates{threshold.Added: 30, threshold.Removed: 0},
				Overrides: map[threshold.Axis]map[string]float64{threshold.Removed: {"cpe/cisco-json": 25}},
			},
		},
		{
			name:    "no axes",
			cfg:     threshold.Config{},
			wantErr: true,
		},
		{
			name:    "default on undeclared axis",
			cfg:     threshold.Config{Axes: []threshold.Axis{threshold.Added}, Default: threshold.Rates{threshold.Changed: 1}},
			wantErr: true,
		},
		{
			name:    "override on undeclared axis",
			cfg:     threshold.Config{Axes: []threshold.Axis{threshold.Added}, Overrides: map[threshold.Axis]map[string]float64{threshold.Changed: {"k": 1}}},
			wantErr: true,
		},
		{
			name:    "negative default",
			cfg:     threshold.Config{Axes: all, Default: threshold.Rates{threshold.Added: -1}},
			wantErr: true,
		},
		{
			name:    "NaN default",
			cfg:     threshold.Config{Axes: all, Default: threshold.Rates{threshold.Added: math.NaN()}},
			wantErr: true,
		},
		{
			name:    "Inf override",
			cfg:     threshold.Config{Axes: all, Overrides: map[threshold.Axis]map[string]float64{threshold.Added: {"k": math.Inf(1)}}},
			wantErr: true,
		},
		{
			name:    "empty override key",
			cfg:     threshold.Config{Axes: all, Overrides: map[threshold.Axis]map[string]float64{threshold.Added: {"": 1}}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigResolve(t *testing.T) {
	cfg := threshold.Config{
		Axes:    all,
		Default: threshold.Rates{threshold.Added: 30, threshold.Changed: 10}, // removed left unset → 0
		Overrides: map[threshold.Axis]map[string]float64{
			threshold.Added:   {"cpe": 50},
			threshold.Removed: {"cpe": 20, "cpe/cisco-json": 40},
		},
	}
	tests := []struct {
		name string
		keys []string
		want threshold.Rates
	}{
		{
			name: "no key hits: defaults, unset axis is 0",
			keys: []string{"alma:8/alma-errata", "alma:8"},
			want: threshold.Rates{threshold.Added: 30, threshold.Changed: 10, threshold.Removed: 0},
		},
		{
			name: "wide key hits per axis independently",
			keys: []string{"cpe/nvd-feed-cve-v2", "cpe"},
			want: threshold.Rates{threshold.Added: 50, threshold.Changed: 10, threshold.Removed: 20},
		},
		{
			name: "narrow key wins over wide key on its axis only",
			keys: []string{"cpe/cisco-json", "cpe"},
			want: threshold.Rates{threshold.Added: 50, threshold.Changed: 10, threshold.Removed: 40},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, cfg.Resolve(tt.keys...)); diff != "" {
				t.Errorf("Resolve() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExceeded(t *testing.T) {
	tests := []struct {
		name       string
		rates      threshold.Rates
		thresholds threshold.Rates
		want       []threshold.Axis
	}{
		{
			name:       "none",
			rates:      threshold.Rates{threshold.Added: 30, threshold.Changed: 10, threshold.Removed: 10},
			thresholds: threshold.Rates{threshold.Added: 30, threshold.Changed: 10, threshold.Removed: 10},
			want:       nil,
		},
		{
			name:       "in axes order",
			rates:      threshold.Rates{threshold.Added: 31, threshold.Changed: 0, threshold.Removed: 0.1},
			thresholds: threshold.Rates{threshold.Added: 30, threshold.Changed: 10},
			want:       []threshold.Axis{threshold.Added, threshold.Removed},
		},
		{
			name:  "nil maps compare as zero",
			rates: nil,
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, threshold.Exceeded(all, tt.rates, tt.thresholds)); diff != "" {
				t.Errorf("Exceeded() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRate(t *testing.T) {
	tests := []struct {
		name        string
		baseline, n int
		want        float64
	}{
		{name: "fraction of baseline", baseline: 200, n: 50, want: 25},
		{name: "can exceed 100", baseline: 2, n: 3, want: 150},
		{name: "empty baseline with units is 100", baseline: 0, n: 2, want: 100},
		{name: "nothing is 0", baseline: 0, n: 0, want: 0},
		{name: "no change is 0", baseline: 10, n: 0, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := threshold.Rate(tt.baseline, tt.n); got != tt.want {
				t.Errorf("Rate(%d, %d) = %v, want %v", tt.baseline, tt.n, got, tt.want)
			}
		})
	}
}

func TestFormat(t *testing.T) {
	rates := threshold.Rates{threshold.Added: 12.34, threshold.Changed: 0, threshold.Removed: 10}
	thresholds := threshold.Rates{threshold.Added: 30, threshold.Changed: 10, threshold.Removed: 5}
	if got, want := threshold.Format(all, rates, thresholds), "12.3% / 0.0% / **10.0%**"; got != want {
		t.Errorf("Format() = %q, want %q", got, want)
	}
	if got, want := threshold.FormatThresholds(all, thresholds), "30.0% / 10.0% / 5.0%"; got != want {
		t.Errorf("FormatThresholds() = %q, want %q", got, want)
	}
	if got, want := threshold.Max(all, rates), 12.34; got != want {
		t.Errorf("Max() = %v, want %v", got, want)
	}
}
