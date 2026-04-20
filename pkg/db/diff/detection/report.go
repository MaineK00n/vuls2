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
	diffs := slices.Collect(maps.Values(diffm))
	slices.SortFunc(diffs, func(a, b FileDiff) int {
		return cmp.Or(
			cmp.Compare(b.ChangeRate, a.ChangeRate),
			cmp.Compare(a.Name, b.Name),
		)
	})

	pass := !slices.ContainsFunc(diffs, func(d FileDiff) bool { return !d.Pass })

	maxName := ""
	maxRate := 0.0
	for _, d := range diffs {
		if d.ChangeRate > maxRate {
			maxRate = d.ChangeRate
			maxName = d.Name
		}
	}
	maxCell := fmt.Sprintf("%.1f%%", maxRate)
	if maxName != "" {
		maxCell = fmt.Sprintf("%.1f%% (%s)", maxRate, maxName)
	}

	if _, err := fmt.Fprintf(w, `# Diff Report: Detection

**Result**: %s
**Change Rate Threshold**: %.1f%%
**Change Rate Max**:       %s

## Summary

| Name | Baseline | Target | Added | Removed | Change Rate | Result |
|------|----------|--------|-------|---------|-------------|--------|
`, resultLabel(pass), changeRateThreshold, maxCell); err != nil {
		return false, errors.Wrap(err, "write header")
	}

	for _, d := range diffs {
		if _, err := fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %.1f%% | %s |\n",
			d.Name, len(d.BaselineIDs), len(d.TargetIDs), len(d.Added), len(d.Removed), d.ChangeRate, resultLabel(d.Pass)); err != nil {
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
			if _, err := fmt.Fprintf(w, "### %s\n\n", d.Name); err != nil {
				return false, errors.Wrapf(err, "write file header %s", d.Name)
			}
			if len(d.Added) > 0 {
				if _, err := fmt.Fprintf(w, "#### Added IDs (%d)\n\n", len(d.Added)); err != nil {
					return false, errors.Wrapf(err, "write added header %s", d.Name)
				}
				slices.Sort(d.Added)
				for _, id := range d.Added {
					if _, err := fmt.Fprintf(w, "- %s\n", id); err != nil {
						return false, errors.Wrapf(err, "write added ID %s", d.Name)
					}
				}
				if _, err := fmt.Fprintln(w); err != nil {
					return false, errors.Wrapf(err, "write added separator %s", d.Name)
				}
			}
			if len(d.Removed) > 0 {
				if _, err := fmt.Fprintf(w, "#### Removed IDs (%d)\n\n", len(d.Removed)); err != nil {
					return false, errors.Wrapf(err, "write removed header %s", d.Name)
				}
				slices.Sort(d.Removed)
				for _, id := range d.Removed {
					if _, err := fmt.Fprintf(w, "- %s\n", id); err != nil {
						return false, errors.Wrapf(err, "write removed ID %s", d.Name)
					}
				}
				if _, err := fmt.Fprintln(w); err != nil {
					return false, errors.Wrapf(err, "write removed separator %s", d.Name)
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
