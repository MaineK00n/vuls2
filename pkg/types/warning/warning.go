// Package warning defines vuls2's own warning vocabulary and the warning
// entry recorded on result types (e.g. detect's DetectResult.Warnings).
package warning

import (
	"cmp"

	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// Kind is vuls2's own warning vocabulary. It is a superset of the upstream
// criteria warning kinds — both are string types, so upstream values convert
// for free — which lets criteria-evaluation warnings and vuls2's own share
// one vocabulary without vuls2 minting values into the upstream namespace.
// That separation keeps the upstream diagnosis sound: there, a value outside
// the build's vocabulary means "produced by a newer vuls-data-update, a
// dependency bump is due", whereas vuls2's own kinds have no such drift
// problem (producer and consumer are the same binary).
type Kind string

// Warning is one non-fatal event recorded on a result. The struct is
// append-only: fields such as a message, location or count can be added
// later without changing the existing ones' meaning.
type Warning struct {
	// Kind is the machine-readable classification.
	Kind Kind `json:"kind,omitempty"`
	// Cause is the concrete datum that triggered the warning, verbatim —
	// for cause-carrying kinds an empty string means the datum was unset,
	// and kinds that carry no cause by design (e.g. the upstream
	// empty-range) leave it empty. Interpretation is per Kind.
	Cause string `json:"cause,omitempty"`
	// Source is the data source the warning is attributable to; empty for
	// warnings that are not about a data source's data.
	Source sourceTypes.SourceID `json:"source,omitempty"`
}

// Compare orders warnings by (Kind, Cause, Source), each lexicographically —
// vuls2 keeps no vocabulary rank for its own kinds. It is the canonical
// comparator for the append-only struct: fields added later are appended to
// the comparison so existing orderings are preserved, and callers comparing
// through it (dedup, sorting) stay source-compatible even when a future
// field makes the struct non-comparable in the Go sense.
func Compare(x, y Warning) int {
	return cmp.Or(
		cmp.Compare(x.Kind, y.Kind),
		cmp.Compare(x.Cause, y.Cause),
		cmp.Compare(x.Source, y.Source),
	)
}
