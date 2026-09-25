package db

import (
	"github.com/MaineK00n/vuls2/pkg/diff/summary"
)

// summarize projects diffs onto the --output-json contract (package summary).
//
// pass is the report's overall verdict. It also covers ecosystems compared
// without per-source data, which the report renders as a "(none)" placeholder
// row; those have no source a consumer could act on and are not emitted, so
// Summary.Pass can be false while every emitted row passes.
func summarize(diffs []EcosystemDiff, pass bool) summary.Summary {
	var rows []summary.Row
	for _, d := range diffs {
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
