package detection

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/pkg/errors"
)

// reportRow flattens (file, source) for rendering and sorting.
type reportRow struct {
	Name string
	SourceDiff
}

// generateReport writes a Markdown report for detection diff to w.
// It returns whether all (file, source) pairs passed and any write error.
func generateReport(w io.Writer, diffm map[string]FileDiff) (bool, error) {
	if len(diffm) == 0 {
		return true, errors.New("no files to compare")
	}

	var rows []reportRow
	for _, d := range slices.Collect(maps.Values(diffm)) {
		for _, sd := range d.Sources {
			rows = append(rows, reportRow{Name: d.Name, SourceDiff: sd})
		}
	}

	// Sort: FAIL first, then by rate desc, then by name asc, source asc.
	// Per-target threshold can hide a high-rate row behind PASS, so surfacing
	// FAIL rows first keeps triage focused on what actually blocks promotion.
	slices.SortFunc(rows, func(a, b reportRow) int {
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
			cmp.Compare(a.SourceID, b.SourceID),
		)
	})
	pass := !slices.ContainsFunc(rows, func(r reportRow) bool { return !r.Pass })

	if _, err := fmt.Fprintf(w, `# Diff Report: Detection

## Summary

**Result**: %s

| Name | Source | Baseline | Target | Added | Removed | Change Rate | Threshold | Result |
|------|--------|----------|--------|-------|---------|-------------|-----------|--------|
`, resultLabel(pass)); err != nil {
		return false, errors.Wrap(err, "write header")
	}

	for _, r := range rows {
		if _, err := fmt.Fprintf(w, "| %s | %s | %d | %d | %d | %d | %.1f%% | %.1f%% | %s |\n",
			r.Name, r.SourceID, len(r.BaselineIDs), len(r.TargetIDs), len(r.Added), len(r.Removed), r.ChangeRate,
			r.Threshold, resultLabel(r.Pass)); err != nil {
			return false, errors.Wrap(err, "write summary row")
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return false, errors.Wrap(err, "write separator")
	}

	// Details for FAIL (file, source) pairs
	var failRows []reportRow
	for _, r := range rows {
		if !r.Pass {
			failRows = append(failRows, r)
		}
	}

	if len(failRows) > 0 {
		if _, err := fmt.Fprintf(w, "## Details (FAIL sources)\n\n"); err != nil {
			return false, errors.Wrap(err, "write details header")
		}
		for _, r := range failRows {
			if _, err := fmt.Fprintf(w, "### %s / %s (%.1f%%)\n\n", r.Name, r.SourceID, r.ChangeRate); err != nil {
				return false, errors.Wrapf(err, "write file header %s/%s", r.Name, r.SourceID)
			}
			if len(r.Added) > 0 {
				slices.Sort(r.Added)
				if err := writeIDList(w, "Added IDs", r.Added); err != nil {
					return false, errors.Wrapf(err, "write added IDs %s/%s", r.Name, r.SourceID)
				}
			}
			if len(r.Removed) > 0 {
				slices.Sort(r.Removed)
				if err := writeIDList(w, "Removed IDs", r.Removed); err != nil {
					return false, errors.Wrapf(err, "write removed IDs %s/%s", r.Name, r.SourceID)
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
