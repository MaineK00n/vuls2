package db

import (
	"github.com/MaineK00n/vuls2/pkg/diff/summary"
)

// summarize projects diffs onto the --output-json contract (package summary),
// one row per row of the report's Summary table.
//
// An ecosystem compared without per-source data on either side is the
// report's "(none)" placeholder row; it is emitted with an empty Source, a
// zero rate and the threshold that would have applied to the ecosystem
// (override resolution with no source), and it always passes since there
// is nothing to compare.
func summarize(diffs []EcosystemDiff, pass bool, threshold float64, overrides map[string]float64) summary.Summary {
	var rows []summary.Row
	for _, d := range diffs {
		if len(d.Sources) == 0 {
			rows = append(rows, summary.Row{
				Name:      string(d.Ecosystem),
				Threshold: resolveThreshold(overrides, threshold, d.Ecosystem, ""),
				Pass:      d.Pass,
			})
			continue
		}
		for _, s := range d.Sources {
			rows = append(rows, summary.Row{
				Name:   string(d.Ecosystem),
				Source: string(s.SourceID),
				// Same rule as the report: a source fails on whichever
				// bucket drifted more.
				ChangeRate: max(s.DetectionChangeRate, s.KBChangeRate),
				Threshold:  s.Threshold,
				Pass:       s.Pass,
			})
		}
	}
	return summary.New(summary.CheckDB, pass, rows)
}
