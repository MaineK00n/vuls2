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

	if _, err := fmt.Fprintf(w, `# Diff Report: Detection

**Result**: %s
**Change Rate Threshold**: %.1f%%
**Change Rate Max**:       %s

## Summary

| Name | Baseline | Target | Added | Removed | Change Rate | Result |
|------|----------|--------|-------|---------|-------------|--------|
`, resultLabel(pass), changeRateThreshold, formatMax(diffs[0].ChangeRate, diffs[0].Name)); err != nil {
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

// formatMax renders a "<rate>% (<name>)" cell for the report header, omitting
// the name part when the rate is 0 (no non-zero change exists).
func formatMax(rate float64, name string) string {
	if rate == 0 {
		return fmt.Sprintf("%.1f%%", rate)
	}
	return fmt.Sprintf("%.1f%% (%s)", rate, name)
}

func resultLabel(pass bool) string {
	if pass {
		return "PASS"
	}
	return "**FAIL**"
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
