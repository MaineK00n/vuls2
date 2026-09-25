// Package summary defines the machine-readable result that `vuls diff db`
// and `vuls diff detection` write when invoked with --output-json.
//
// The JSON is a CLI contract consumed by CI (vuls-data-db's diff-guard
// action decides which data sources to hold back from it), and the consumer
// may lag behind this producer by weeks. The shape is therefore deliberately
// minimal and frozen:
//
//   - Only the fields below are emitted; counts and ID lists stay in the
//     Markdown report.
//   - Every field is always present. rows is never null (an empty result is
//     []), change_rate and threshold are always numbers.
//   - rows is sorted by (name, source) so output is deterministic.
//   - Adding a field keeps SchemaVersion; removing, renaming or retyping one
//     bumps it. Consumers must check schema_version and ignore unknown fields.
//
// Example:
//
//	{
//	  "schema_version": 1,
//	  "check": "db",
//	  "pass": false,
//	  "rows": [
//	    {"name": "redhat:10", "source": "redhat-vex", "change_rate": 6.5, "threshold": 5, "pass": false}
//	  ]
//	}
package summary

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"slices"

	"github.com/pkg/errors"
)

// SchemaVersion is the current value of the schema_version field.
const SchemaVersion = 1

// Check identifies which diff command produced the summary.
type Check string

const (
	CheckDB        Check = "db"
	CheckDetection Check = "detection"
)

// Summary is the top-level JSON document.
type Summary struct {
	SchemaVersion int   `json:"schema_version"`
	Check         Check `json:"check"`
	// Pass is the overall result and matches the command's exit status. It
	// can be false while every row passes when the report contains rows
	// that have no data source (see Row).
	Pass bool  `json:"pass"`
	Rows []Row `json:"rows"`
}

// Row is one (name, source) pair of the report's Summary table.
//
// Rows without a data source (the report's "(none)" placeholder for an
// ecosystem or file compared without per-source data) are not emitted: they
// name nothing a consumer could act on.
type Row struct {
	// Name is the ecosystem (db, e.g. "redhat:10") or the scan-result file
	// basename without ".json" (detection, e.g. "rhel_10"): the same string
	// the left-hand side of a --change-rate-threshold-override entry uses.
	Name string `json:"name"`
	// Source is the data source ID, as `vuls db search datasources` prints
	// it in "id".
	Source string `json:"source"`
	// ChangeRate is the change rate (%) the threshold was applied to. For
	// db it is the larger of the detection and KB rates.
	ChangeRate float64 `json:"change_rate"`
	// Threshold is the threshold (%) applied to this row after override
	// resolution.
	Threshold float64 `json:"threshold"`
	Pass      bool    `json:"pass"`
}

// New assembles a Summary, normalizing rows so that the encoding is
// deterministic: rows is sorted by (name, source) and never nil.
func New(check Check, pass bool, rows []Row) Summary {
	rs := slices.Clone(rows)
	if rs == nil {
		rs = []Row{}
	}
	slices.SortFunc(rs, func(a, b Row) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Source, b.Source))
	})
	return Summary{SchemaVersion: SchemaVersion, Check: check, Pass: pass, Rows: rs}
}

// Write encodes s to w as indented JSON followed by a newline.
func (s Summary) Write(w io.Writer) error {
	if err := json.MarshalWrite(w, s, jsontext.WithIndent("  ")); err != nil {
		return errors.Wrap(err, "marshal summary")
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return errors.Wrap(err, "write trailing newline")
	}
	return nil
}
