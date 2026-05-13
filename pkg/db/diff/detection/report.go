package detection

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/pkg/errors"
)

// generateReport writes a Markdown report for detection diff to w.
// It returns whether all files passed and any write error.
func generateReport(w io.Writer, diffm map[string]FileDiff, changeRateThreshold float64) (bool, error) {
	if len(diffm) == 0 {
		return true, errors.New("no files to compare")
	}

	diffs := slices.Collect(maps.Values(diffm))
	// Sort: FAIL first, then by rate desc, then by name asc.
	// Per-target threshold can hide a high-rate row behind PASS, so surfacing
	// FAIL rows first keeps triage focused on what actually blocks promotion.
	slices.SortFunc(diffs, func(a, b FileDiff) int {
		return cmp.Or(
			func() int {
				switch {
				case !a.Pass && b.Pass:
					return -1
				case a.Pass && !b.Pass:
					return +1
				default:
					return 0
				}
			}(),
			cmp.Compare(b.ChangeRate, a.ChangeRate),
			cmp.Compare(a.Name, b.Name),
		)
	})
	pass := !slices.ContainsFunc(diffs, func(d FileDiff) bool { return !d.Pass })

	if _, err := fmt.Fprintf(w, `# Diff Report: Detection

## Summary

**Result**: %s (Default Change Rate Threshold: %.1f%%)

| Name | Baseline | Target | Added | Removed | Change Rate | Override | Result |
|------|----------|--------|-------|---------|-------------|----------|--------|
`, resultLabel(pass), changeRateThreshold); err != nil {
		return false, errors.Wrap(err, "write header")
	}

	for _, d := range diffs {
		if _, err := fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %.1f%% | %s | %s |\n",
			d.Name, len(d.BaselineIDs), len(d.TargetIDs), len(d.Added), len(d.Removed), d.ChangeRate,
			overrideLabel(d.Threshold, d.ThresholdOverridden), resultLabel(d.Pass)); err != nil {
			return false, errors.Wrap(err, "write summary row")
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return false, errors.Wrap(err, "write separator")
	}

	// Details for FAIL files
	var failDiffs []FileDiff
	for _, d := range diffs {
		if !d.Pass {
			failDiffs = append(failDiffs, d)
		}
	}

	if len(failDiffs) > 0 {
		if _, err := fmt.Fprintf(w, "## Details (FAIL files)\n\n"); err != nil {
			return false, errors.Wrap(err, "write details header")
		}
		for _, d := range failDiffs {
			if _, err := fmt.Fprintf(w, "### %s (%.1f%%)\n\n", d.Name, d.ChangeRate); err != nil {
				return false, errors.Wrapf(err, "write file header %s", d.Name)
			}
			if len(d.Added) > 0 {
				slices.Sort(d.Added)
				if err := writeIDList(w, "Added IDs", d.Added); err != nil {
					return false, errors.Wrapf(err, "write added IDs %s", d.Name)
				}
			}
			if len(d.Removed) > 0 {
				slices.Sort(d.Removed)
				if err := writeIDList(w, "Removed IDs", d.Removed); err != nil {
					return false, errors.Wrapf(err, "write removed IDs %s", d.Name)
				}
			}
		}
	}

	return pass, nil
}

func resultLabel(pass bool) string {
	if pass {
		return "PASS"
	}
	return "**FAIL**"
}

// overrideLabel renders the override threshold (e.g. "25.0%") for rows where
// an override matched, and an empty cell otherwise. Default-threshold rows
// stay blank because the default value is already shown in the summary
// header — duplicating it per-row added noise without useful signal.
func overrideLabel(t float64, overridden bool) string {
	if overridden {
		return fmt.Sprintf("%.1f%%", t)
	}
	return ""
}

// writeIDList writes a "#### <label> (N)" section with a bulleted list of IDs.
// It is a no-op when ids is empty.
func writeIDList(w io.Writer, label string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "#### %s (%d)\n\n", label, len(ids)); err != nil {
		return errors.Wrap(err, "write header")
	}
	for _, id := range ids {
		if _, err := fmt.Fprintf(w, "- %s\n", id); err != nil {
			return errors.Wrap(err, "write id")
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return errors.Wrap(err, "write separator")
	}
	return nil
}
