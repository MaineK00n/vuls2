// Package threshold holds the per-axis change-rate thresholds shared by
// `vuls diff db` and `vuls diff detection`. A diff is judged on up to three
// axes — added, changed, removed — each with its own default threshold and
// its own per-target overrides, so that routine additions can be tolerated
// while removals stay tightly bounded.
package threshold

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// Axis is one direction of change a diff is judged on.
type Axis string

const (
	// Added counts units present only in the target.
	Added Axis = "added"
	// Changed counts units present on both sides under the same key but
	// with different content. Only diffs that compare content have it;
	// `diff detection` compares ID sets and never reports it.
	Changed Axis = "changed"
	// Removed counts units present only in the baseline.
	Removed Axis = "removed"
)

// Rates maps an axis to a percentage: either a change rate or a threshold.
type Rates map[Axis]float64

// Threshold is the per-axis threshold set of one diff command.
type Threshold struct {
	// Axes the command judges, in report order. Default and Overrides may
	// only mention these.
	Axes []Axis
	// Default threshold per axis. A missing axis means 0 (no change
	// tolerated on it).
	Default Rates
	// Overrides per axis, keyed by target (e.g. "ubuntu:26.04" or
	// "cpe/cisco-json" for db; "debian_13" or "cpe_jvn/jvn-feed-rss" for
	// detection). Resolve looks keys up in precedence order.
	Overrides map[Axis]map[string]float64
}

// Legacy builds the Threshold equivalent to the single-threshold flags
// (`--change-rate-threshold` / `--change-rate-threshold-override`): the
// default and every override apply to all axes alike. Each axis rate is at
// most the legacy combined rate, so the mapping is never stricter than the
// legacy judgement.
func Legacy(axes []Axis, def float64, overrides map[string]float64) Threshold {
	t := Threshold{Axes: axes, Default: make(Rates, len(axes)), Overrides: make(map[Axis]map[string]float64, len(axes))}
	for _, a := range axes {
		t.Default[a] = def
		if len(overrides) > 0 {
			m := make(map[string]float64, len(overrides))
			for k, v := range overrides {
				m[k] = v
			}
			t.Overrides[a] = m
		}
	}
	return t
}

// Validate checks that Default and Overrides only mention declared axes
// and only carry finite, non-negative rates.
func (t Threshold) Validate() error {
	if len(t.Axes) == 0 {
		return errors.New("unexpected axes. expected: non-empty, actual: empty")
	}
	for a, v := range t.Default {
		if !slices.Contains(t.Axes, a) {
			return errors.Errorf("unexpected default axis. expected: one of %v, actual: %q", t.Axes, a)
		}
		if err := validateValue(v); err != nil {
			return errors.Wrapf(err, "validate default of %s axis", a)
		}
	}
	for a, m := range t.Overrides {
		if !slices.Contains(t.Axes, a) {
			return errors.Errorf("unexpected override axis. expected: one of %v, actual: %q", t.Axes, a)
		}
		for k, v := range m {
			if k == "" {
				return errors.Errorf("unexpected override key. expected: non-empty, actual: %q (axis: %s)", k, a)
			}
			if err := validateValue(v); err != nil {
				return errors.Wrapf(err, "validate override of %s axis for %q", a, k)
			}
		}
	}
	return nil
}

// validateValue rejects a NaN / ±Inf / negative threshold value. The judgement is
// `rate > threshold`, so a NaN threshold makes every comparison false and
// lets every diff PASS however large the change; +Inf likewise PASSes
// everything; a negative threshold can never be met.
func validateValue(f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errors.Errorf("unexpected value. expected: finite, actual: %v", f)
	}
	if f < 0 {
		return errors.Errorf("unexpected value. expected: >= 0, actual: %v", f)
	}
	return nil
}

// Resolve returns the threshold of every axis for one target. keys are the
// override keys to try, narrowest first (e.g. "cpe/cisco-json", then
// "cpe"); the first hit wins per axis, and an axis with no hit falls back to
// Default (0 when absent). The result carries every axis in t.Axes.
func (t Threshold) Resolve(keys ...string) Rates {
	r := make(Rates, len(t.Axes))
	for _, a := range t.Axes {
		r[a] = t.Default[a]
		for _, k := range keys {
			if v, ok := t.Overrides[a][k]; ok {
				r[a] = v
				break
			}
		}
	}
	return r
}

// Exceeded returns, in axes order, the axes whose rate is above its
// threshold. A missing rate or threshold counts as 0.
func Exceeded(axes []Axis, rates, thresholds Rates) []Axis {
	var out []Axis
	for _, a := range axes {
		if rates[a] > thresholds[a] {
			out = append(out, a)
		}
	}
	return out
}

// Rate computes one axis' change rate as a percentage of the baseline unit
// count: n / baseline * 100. When baseline is 0 but n > 0 the rate is 100
// (only the added axis can get here — changed and removed units are drawn
// from the baseline); when both are 0 it is 0. The added rate can exceed
// 100% when additions outnumber baseline entries — capping would hide the
// magnitude of large additions.
func Rate(baseline, n int) float64 {
	switch {
	case baseline > 0:
		return float64(n) / float64(baseline) * 100
	case n > 0:
		return 100
	default:
		return 0
	}
}

// Format renders rates in axes order as "a% / b% / c%", wrapping in bold
// the ones above their threshold so a FAIL row shows which axis tripped.
// Each rate is printed with enough decimals to agree with the judgement
// against its rendered threshold (see formatRate), so 10.04% over 10%
// renders as "**10.04%**" rather than a "**10.0%**" that looks equal to
// "10.0%", and 10.05% under 10.051% renders as "10.050%" rather than a
// "10.1%" that looks above it.
func Format(axes []Axis, rates, thresholds Rates) string {
	cells := make([]string, 0, len(axes))
	for _, a := range axes {
		cell := fmt.Sprintf("%s%%", formatRate(rates[a], thresholds[a]))
		if rates[a] > thresholds[a] {
			cell = fmt.Sprintf("**%s**", cell)
		}
		cells = append(cells, cell)
	}
	return strings.Join(cells, " / ")
}

// FormatExceeded renders "rate% > threshold%" for an exceeded axis with
// just enough decimals for the inequality to read as true: at one decimal
// 10.010% over a 10% threshold would print as "10.0% > 10.0%".
func FormatExceeded(rate, threshold float64) string {
	return fmt.Sprintf("%s%% > %s%%", formatRate(rate, threshold), formatThreshold(threshold))
}

// formatThreshold renders a threshold exactly: an operator-supplied value
// such as 10.06 keeps every significant decimal, so the printed threshold
// is never rounded past the rate it is compared with; values with at most
// one decimal render as "%.1f" ("10.0", "12.5") for a uniform column.
func formatThreshold(t float64) string {
	s := strconv.FormatFloat(t, 'f', -1, 64)
	if _, frac, _ := strings.Cut(s, "."); len(frac) <= 1 {
		return fmt.Sprintf("%.1f", t)
	}
	return s
}

// formatRate renders a rate with the smallest precision — at least one
// decimal and at least the threshold's own — at which the printed value
// sits on the same side of the printed threshold as the judgement: above
// it when the rate exceeds the threshold, at or below it otherwise. The
// report thus never shows a failing rate that looks at or below its
// threshold, nor a passing rate that looks above it. Precision grows up to
// six decimals, past which the rate is printed with %g.
func formatRate(rate, threshold float64) string {
	ts := formatThreshold(threshold)
	tv, _ := strconv.ParseFloat(ts, 64)
	exceeded := rate > threshold
	p := 1
	if _, frac, _ := strings.Cut(ts, "."); len(frac) > p {
		p = len(frac)
	}
	for ; p <= 6; p++ {
		rs := fmt.Sprintf("%.*f", p, rate)
		rv, _ := strconv.ParseFloat(rs, 64)
		if (rv > tv) == exceeded {
			return rs
		}
	}
	return fmt.Sprintf("%g", rate)
}

// FormatThresholds renders thresholds in axes order as "a% / b% / c%".
func FormatThresholds(axes []Axis, thresholds Rates) string {
	cells := make([]string, 0, len(axes))
	for _, a := range axes {
		cells = append(cells, fmt.Sprintf("%s%%", formatThreshold(thresholds[a])))
	}
	return strings.Join(cells, " / ")
}

// Max returns the largest rate over axes (0 when none).
func Max(axes []Axis, rates Rates) float64 {
	m := 0.0
	for _, a := range axes {
		m = max(m, rates[a])
	}
	return m
}
