package threshold_test

import (
	"maps"
	"math"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls2/pkg/diff/threshold"
)

func TestLegacy(t *testing.T) {
	tests := []struct {
		name      string
		axes      []threshold.Axis
		def       float64
		overrides map[string]float64
		want      threshold.Threshold
	}{
		{
			name: "default on every axis, no overrides",
			axes: []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
			def:  10,
			want: threshold.Threshold{
				Axes:      []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
				Default:   threshold.Rates{threshold.Added: 10, threshold.Changed: 10, threshold.Removed: 10},
				Overrides: map[string]threshold.Rates{},
			},
		},
		{
			name:      "overrides copied onto every axis",
			axes:      []threshold.Axis{threshold.Added, threshold.Removed},
			def:       5,
			overrides: map[string]float64{"debian_13": 15, "cpe_jvn/jvn-feed-rss": 25},
			want: threshold.Threshold{
				Axes:    []threshold.Axis{threshold.Added, threshold.Removed},
				Default: threshold.Rates{threshold.Added: 5, threshold.Removed: 5},
				Overrides: map[string]threshold.Rates{
					"debian_13":            {threshold.Added: 15, threshold.Removed: 15},
					"cpe_jvn/jvn-feed-rss": {threshold.Added: 25, threshold.Removed: 25},
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
			// The per-key Rates must be independent copies: mutating one
			// key's overrides must not leak into another.
			if keys := slices.Sorted(maps.Keys(tt.overrides)); len(keys) > 1 {
				got.Overrides[keys[0]]["mutated"] = 1
				if _, leaked := got.Overrides[keys[1]]["mutated"]; leaked {
					t.Error("Legacy() shares one Rates between override keys")
				}
			}
		})
	}
}

func TestThresholdValidate(t *testing.T) {
	tests := []struct {
		name    string
		th      threshold.Threshold
		wantErr bool
	}{
		{
			name: "valid",
			th: threshold.Threshold{
				Axes:      []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
				Default:   threshold.Rates{threshold.Added: 30, threshold.Removed: 0},
				Overrides: map[string]threshold.Rates{"cpe/cisco-json": {threshold.Removed: 25}},
			},
		},
		{
			name:    "no axes",
			th:      threshold.Threshold{},
			wantErr: true,
		},
		{
			name: "default on undeclared axis",
			th: threshold.Threshold{
				Axes:    []threshold.Axis{threshold.Added},
				Default: threshold.Rates{threshold.Changed: 1},
			},
			wantErr: true,
		},
		{
			name: "override on undeclared axis",
			th: threshold.Threshold{
				Axes:      []threshold.Axis{threshold.Added},
				Overrides: map[string]threshold.Rates{"k": {threshold.Changed: 1}},
			},
			wantErr: true,
		},
		{
			name: "negative default",
			th: threshold.Threshold{
				Axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
				Default: threshold.Rates{threshold.Added: -1},
			},
			wantErr: true,
		},
		{
			name: "NaN default",
			th: threshold.Threshold{
				Axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
				Default: threshold.Rates{threshold.Added: math.NaN()},
			},
			wantErr: true,
		},
		{
			name: "Inf override",
			th: threshold.Threshold{
				Axes:      []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
				Overrides: map[string]threshold.Rates{"k": {threshold.Added: math.Inf(1)}},
			},
			wantErr: true,
		},
		{
			name: "empty override key",
			th: threshold.Threshold{
				Axes:      []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
				Overrides: map[string]threshold.Rates{"": {threshold.Added: 1}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.th.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestThresholdResolve(t *testing.T) {
	th := threshold.Threshold{
		Axes:    []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed},
		Default: threshold.Rates{threshold.Added: 30, threshold.Changed: 10}, // removed left unset → 0
		Overrides: map[string]threshold.Rates{
			"cpe":            {threshold.Added: 50, threshold.Removed: 20},
			"cpe/cisco-json": {threshold.Removed: 40},
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
			if diff := cmp.Diff(tt.want, th.Resolve(tt.keys...)); diff != "" {
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
			if diff := cmp.Diff(tt.want, threshold.Exceeded([]threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, tt.rates, tt.thresholds)); diff != "" {
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

func TestFormatExceeded(t *testing.T) {
	tests := []struct {
		name            string
		rate, threshold float64
		want            string
	}{
		{name: "one decimal", rate: 12.34, threshold: 10, want: "12.3% > 10.0%"},
		{name: "zero threshold", rate: 2.5, threshold: 0, want: "2.5% > 0.0%"},
		// The judgement is on the unrounded values, so both sides may print
		// equal.
		{name: "rounds to the threshold", rate: 100.0 / 999 * 100, threshold: 10, want: "10.0% > 10.0%"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := threshold.FormatExceeded(tt.rate, tt.threshold); got != tt.want {
				t.Errorf("FormatExceeded(%v, %v) = %q, want %q", tt.rate, tt.threshold, got, tt.want)
			}
		})
	}
}

func TestFormat(t *testing.T) {
	tests := []struct {
		name       string
		rates      threshold.Rates
		thresholds threshold.Rates
		want       string
	}{
		{
			name:       "exceeded cell in bold",
			rates:      threshold.Rates{threshold.Added: 12.34, threshold.Changed: 0, threshold.Removed: 10},
			thresholds: threshold.Rates{threshold.Added: 30, threshold.Changed: 10, threshold.Removed: 5},
			want:       "12.3% / 0.0% / **10.0%**",
		},
		{
			// Bold follows the unrounded judgement: an exceeded rate may
			// print equal to its threshold.
			name:       "exceeded cell that rounds to its threshold",
			rates:      threshold.Rates{threshold.Added: 10.04, threshold.Changed: 9.96, threshold.Removed: 0},
			thresholds: threshold.Rates{threshold.Added: 10, threshold.Changed: 10, threshold.Removed: 0},
			want:       "**10.0%** / 10.0% / 0.0%",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := threshold.Format([]threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, tt.rates, tt.thresholds); got != tt.want {
				t.Errorf("Format() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatThresholds(t *testing.T) {
	tests := []struct {
		name       string
		thresholds threshold.Rates
		want       string
	}{
		{
			name:       "whole numbers at one decimal",
			thresholds: threshold.Rates{threshold.Added: 30, threshold.Changed: 10, threshold.Removed: 5},
			want:       "30.0% / 10.0% / 5.0%",
		},
		{
			name:       "one decimal",
			thresholds: threshold.Rates{threshold.Added: 10.06, threshold.Changed: 12.5, threshold.Removed: 0},
			want:       "10.1% / 12.5% / 0.0%",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := threshold.FormatThresholds([]threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, tt.thresholds); got != tt.want {
				t.Errorf("FormatThresholds() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMax(t *testing.T) {
	tests := []struct {
		name  string
		rates threshold.Rates
		want  float64
	}{
		{name: "largest over axes", rates: threshold.Rates{threshold.Added: 12.34, threshold.Changed: 0, threshold.Removed: 10}, want: 12.34},
		{name: "unset axes count as 0", rates: threshold.Rates{threshold.Changed: 3}, want: 3},
		{name: "nil is 0", rates: nil, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := threshold.Max([]threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}, tt.rates); got != tt.want {
				t.Errorf("Max() = %v, want %v", got, tt.want)
			}
		})
	}
}
