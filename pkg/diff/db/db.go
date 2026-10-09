package db

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"runtime"
	"slices"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sync/errgroup"

	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

	"github.com/MaineK00n/vuls2/pkg/diff/threshold"
)

// Axes are the change axes `diff db` judges, in report order. Units are
// compared by content, so a unit that stays under the same key with
// different content is counted as changed rather than as a removal plus an
// addition.
var Axes = []threshold.Axis{threshold.Added, threshold.Changed, threshold.Removed}

// Defaults are the built-in per-axis thresholds (%) applied when no
// threshold option is given: additions are the routine pattern of
// vulnerability data and get a generous default; changes and removals
// keep the value the single-threshold guard ran with.
var Defaults = threshold.Rates{threshold.Added: 30, threshold.Changed: 10, threshold.Removed: 10}

type options struct {
	// thresholds is the per-axis configuration (WithThresholds); nil means
	// Defaults.
	thresholds *threshold.Config

	writer io.Writer
	debug  bool
}

type Option interface {
	apply(*options)
}

type thresholdsOption threshold.Config

func (o thresholdsOption) apply(opts *options) {
	c := threshold.Config(o)
	opts.thresholds = &c
}

// WithThresholds supplies the per-axis thresholds. Override keys are either
// an ecosystem identifier (e.g. "ubuntu:26.04"), which applies to every
// source in that ecosystem, or "<ecosystem>/<source ID>" (e.g.
// "cpe/cisco-json"), which applies to a single source and takes precedence
// over the ecosystem-wide key. Values are percentages. An axis or key with
// no override falls back to the config's default for that axis. Without
// this option the diff judges on Defaults.
func WithThresholds(c threshold.Config) Option {
	return thresholdsOption(c)
}

type writerOption struct{ w io.Writer }

func (o writerOption) apply(opts *options) {
	opts.writer = o.w
}

func WithWriter(w io.Writer) Option {
	return writerOption{w: w}
}

type debugOption bool

func (o debugOption) apply(opts *options) {
	opts.debug = bool(o)
}

func WithDebug(d bool) Option {
	return debugOption(d)
}

// SourceDiff holds the comparison result for a single data source within an
// ecosystem. The change rate is computed per source so that a large source
// (e.g. nvd-feed-cve-v2 in the cpe ecosystem) cannot mask a regression in a
// small source (e.g. cisco-json) sharing the same ecosystem bucket.
//
// A source may contribute to a `detection` sub-bucket, a `kb` sub-bucket, or
// both. Each is diffed independently and has its own change rates so that
// disparities in magnitude (e.g. many detection units vs few KB units) do not
// hide a large relative change in the smaller bucket.
// A source Passes only when every axis of both buckets is within its
// threshold.
type SourceDiff struct {
	SourceID sourceTypes.SourceID

	// Detection bucket diff (`<ecosystem>/detection/<Root ID>`), restricted
	// to the entries this source contributes to.
	BaselineKeys       int      // root IDs whose baseline value contains this source
	TargetKeys         int      // root IDs whose target value contains this source
	Added              []string // root IDs where this source appears only in target
	Removed            []string // root IDs where this source appears only in baseline
	Changed            []string // root IDs in both but with different detection data for this source
	BaselineCriterions int      // total leaf criterion count for this source across all baseline root IDs
	TargetCriterions   int      // total leaf criterion count for this source across all target root IDs
	MatchedCriterions  int      // criterions structurally identical in both (Sort + Compare == 0)
	// Unmatched criterions split per axis. Within one root ID, unmatched
	// baseline criterions are paired with unmatched target criterions as
	// Changed; the surplus on either side is Removed or Added. Invariants:
	//   BaselineCriterions = MatchedCriterions + ChangedCriterions + RemovedCriterions
	//   TargetCriterions   = MatchedCriterions + ChangedCriterions + AddedCriterions
	AddedCriterions   int
	ChangedCriterions int
	RemovedCriterions int

	// KB bucket diff (`<ecosystem>/kb/<KB ID>`), restricted to the entries
	// this source contributes to. A source stores at most one KB record per
	// KB ID, so a per-source unit count would always equal the key count —
	// only key counts are kept.
	BaselineKBKeys int      // KB IDs whose baseline value contains this source
	TargetKBKeys   int      // KB IDs whose target value contains this source
	AddedKBs       []string // KB IDs where this source appears only in target
	RemovedKBs     []string // KB IDs where this source appears only in baseline
	ChangedKBs     []string // KB IDs in both but with different KB data for this source
	MatchedKBs     int      // KB IDs whose record is structurally identical in both (Sort + Compare == 0)

	// Per-bucket change rates, one per axis in Axes, each as a percentage
	// of the bucket's baseline unit count. The KB bucket's units are its
	// keys, so its rates come straight from the Added/Changed/RemovedKBs
	// lengths. When a bucket is absent in both baseline and target, its
	// rates are 0.
	DetectionRates threshold.Rates
	KBRates        threshold.Rates

	// Thresholds actually applied to this source, one per axis (post
	// override resolution: "<ecosystem>/<source>" > "<ecosystem>" > default).
	Thresholds threshold.Rates

	Pass bool
}

// EcosystemDiff holds the comparison result for a single ecosystem, broken
// down per data source. An ecosystem Passes only when every source passes.
type EcosystemDiff struct {
	Ecosystem ecosystemTypes.Ecosystem
	Sources   []SourceDiff // unordered; the report sorts for presentation
	Pass      bool
}

// DiffBoltDB compares detection data directly between two BoltDB files.
// This intentionally bypasses the Storage abstraction layer and operates on
// *bolt.DB directly, because the merge-join algorithm requires sorted cursor
// iteration across two databases simultaneously — a capability the Storage
// interface does not (and should not) expose. If the storage engine changes,
// this function will need a corresponding rewrite.
func DiffBoltDB(baselinePath, targetPath string, opts ...Option) error {
	o := &options{
		writer: os.Stdout,
		debug:  false,
	}
	for _, opt := range opts {
		opt.apply(o)
	}

	cfg, err := o.config()
	if err != nil {
		return errors.Wrap(err, "resolve thresholds")
	}

	if o.debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})))
	}

	baselineDB, err := bolt.Open(baselinePath, 0400, &bolt.Options{ReadOnly: true})
	if err != nil {
		return errors.Wrapf(err, "open baseline DB %s", baselinePath)
	}
	defer baselineDB.Close()

	targetDB, err := bolt.Open(targetPath, 0400, &bolt.Options{ReadOnly: true})
	if err != nil {
		return errors.Wrapf(err, "open target DB %s", targetPath)
	}
	defer targetDB.Close()

	results, err := computeDiffs(baselineDB, targetDB, cfg)
	if err != nil {
		return errors.Wrap(err, "compute diffs")
	}

	pass, err := generateReport(o.writer, results)
	if err != nil {
		return errors.Wrap(err, "generate report")
	}

	if !pass {
		// Resolved per-source thresholds are rendered per row in the
		// report's Threshold column, so the exit error stays threshold-free
		// to avoid implying the default was the one that tripped.
		return errors.New("diff failed: detection and/or KB change rate exceeded the applicable threshold on at least one axis (added / changed / removed) for at least one (ecosystem, source) pair; see report for details")
	}
	return nil
}

// config resolves the threshold configuration: the per-axis config when
// given, else Defaults. A config whose Axes differ from this command's
// Axes is rejected — the judged axes are fixed by the command, not by the
// caller, so a config that omits an axis cannot silently disable its
// check.
func (o *options) config() (threshold.Config, error) {
	cfg := threshold.Config{Axes: Axes, Default: Defaults}
	if o.thresholds != nil {
		cfg = *o.thresholds
	}
	if !slices.Equal(cfg.Axes, Axes) {
		return threshold.Config{}, errors.Errorf("unexpected threshold axes. expected: %v, actual: %v", Axes, cfg.Axes)
	}
	if err := cfg.Validate(); err != nil {
		return threshold.Config{}, errors.Wrap(err, "validate thresholds")
	}
	return cfg, nil
}

func computeDiffs(baselineDB, targetDB *bolt.DB, cfg threshold.Config) ([]EcosystemDiff, error) {
	baselineEcos, err := getEcosystems(baselineDB)
	if err != nil {
		return nil, errors.Wrap(err, "get baseline ecosystems")
	}
	if len(baselineEcos) == 0 {
		return nil, errors.New("no ecosystems found in baseline DB")
	}

	total := len(baselineEcos)
	workers := max(1, min(runtime.NumCPU(), total))
	ch := make(chan EcosystemDiff, total)
	g, _ := errgroup.WithContext(context.TODO())
	g.SetLimit(workers)

	slog.Info("Starting DB diff", "ecosystems", total, "workers", workers)

	// Compare only ecosystems present in the baseline.
	// New ecosystems in the target are feature additions, not regressions,
	// so they are intentionally excluded from change rate calculation.
	for _, eco := range baselineEcos {
		g.Go(func() error {
			slog.Debug("ecosystem diff start", "ecosystem", eco)

			d, err := diffEcosystem(baselineDB, targetDB, eco, cfg)
			if err != nil {
				return errors.Wrapf(err, "diff ecosystem %s", string(eco))
			}

			slog.Debug("ecosystem diff done", "ecosystem", eco, "pass", d.Pass, "sources", len(d.Sources))
			ch <- d
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, errors.Wrap(err, "diff ecosystems")
	}
	close(ch)

	results := make([]EcosystemDiff, 0, total)
	for d := range ch {
		results = append(results, d)
	}
	return results, nil
}

// rates computes a bucket's per-axis change rates from its unit counts.
func rates(baseline, added, changed, removed int) threshold.Rates {
	return threshold.Rates{
		threshold.Added:   threshold.Rate(baseline, added),
		threshold.Changed: threshold.Rate(baseline, changed),
		threshold.Removed: threshold.Rate(baseline, removed),
	}
}

// getEcosystems returns ecosystems that have detection or KB data.
func getEcosystems(db *bolt.DB) ([]ecosystemTypes.Ecosystem, error) {
	var ecos []ecosystemTypes.Ecosystem
	if err := db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			switch string(name) {
			case "metadata", "vulnerability", "attack", "capec", "cwe", "datasource":
			default:
				ecos = append(ecos, ecosystemTypes.Ecosystem(name))
			}
			return nil
		})
	}); err != nil {
		return nil, errors.Wrap(err, "db view")
	}
	return ecos, nil
}

// diffEcosystem compares an ecosystem between two DBs by diffing each of its
// sub-buckets (detection, kb) independently, accumulating counts per data
// source. Either sub-bucket may be absent. Per-source thresholds are
// resolved per axis from cfg ("<ecosystem>/<source>" > "<ecosystem>" >
// default) and judged on this package's Axes; cfg.Axes is expected to
// equal Axes (DiffBoltDB enforces it).
func diffEcosystem(baselineDB, targetDB *bolt.DB, ecosystem ecosystemTypes.Ecosystem, cfg threshold.Config) (EcosystemDiff, error) {
	diff := EcosystemDiff{Ecosystem: ecosystem}
	agg := make(map[sourceTypes.SourceID]SourceDiff)
	skipped := make(map[sourceTypes.SourceID]int)

	if err := baselineDB.View(func(btx *bolt.Tx) error {
		return targetDB.View(func(ttx *bolt.Tx) error {
			bEco := btx.Bucket([]byte(ecosystem))
			tEco := ttx.Bucket([]byte(ecosystem))

			var bDet, tDet *bolt.Bucket
			if bEco != nil {
				bDet = bEco.Bucket([]byte("detection"))
			}
			if tEco != nil {
				tDet = tEco.Bucket([]byte("detection"))
			}
			if err := updateDetectionDiff(bDet, tDet, agg, skipped); err != nil {
				return errors.Wrap(err, "diff detection bucket")
			}

			var bKB, tKB *bolt.Bucket
			if bEco != nil {
				bKB = bEco.Bucket([]byte("kb"))
			}
			if tEco != nil {
				tKB = tEco.Bucket([]byte("kb"))
			}
			if err := updateKBDiff(bKB, tKB, agg); err != nil {
				return errors.Wrap(err, "diff kb bucket")
			}

			return nil
		})
	}); err != nil {
		return EcosystemDiff{}, errors.Wrap(err, "diff ecosystem")
	}

	// One aggregated warning per source keeps a widespread extraction bug
	// from flooding the log with per-root-ID lines.
	for sid, n := range skipped {
		slog.Warn("skipped source with no criterions", "ecosystem", ecosystem, "source", sid, "root IDs", n)
	}

	diff.Sources = make([]SourceDiff, 0, len(agg))
	for sid, sd := range agg {
		sd.SourceID = sid
		sd.DetectionRates = rates(sd.BaselineCriterions, sd.AddedCriterions, sd.ChangedCriterions, sd.RemovedCriterions)
		sd.KBRates = rates(sd.BaselineKBKeys, len(sd.AddedKBs), len(sd.ChangedKBs), len(sd.RemovedKBs))
		sd.Thresholds = cfg.Resolve(fmt.Sprintf("%s/%s", ecosystem, sid), string(ecosystem))
		sd.Pass = len(threshold.Exceeded(Axes, sd.DetectionRates, sd.Thresholds)) == 0 &&
			len(threshold.Exceeded(Axes, sd.KBRates, sd.Thresholds)) == 0
		diff.Sources = append(diff.Sources, sd)
	}
	diff.Pass = !slices.ContainsFunc(diff.Sources, func(s SourceDiff) bool { return !s.Pass })
	return diff, nil
}

// mergeBuckets walks two buckets in sorted key order, calling visit once per
// key with the baseline/target values (nil where that side lacks the key).
// Either bucket may be nil.
func mergeBuckets(b, t *bolt.Bucket, visit func(key, bv, tv []byte) error) error {
	switch {
	case b == nil && t == nil:
		return nil
	case b == nil:
		return t.ForEach(func(k, v []byte) error { return visit(k, nil, v) })
	case t == nil:
		return b.ForEach(func(k, v []byte) error { return visit(k, v, nil) })
	}

	bc, tc := b.Cursor(), t.Cursor()
	bk, bv := bc.First()
	tk, tv := tc.First()
	for bk != nil || tk != nil {
		switch {
		case tk == nil || (bk != nil && bytes.Compare(bk, tk) < 0): // baseline-only key
			if err := visit(bk, bv, nil); err != nil {
				return err
			}
			bk, bv = bc.Next()
		case bk == nil || bytes.Compare(bk, tk) > 0: // target-only key
			if err := visit(tk, nil, tv); err != nil {
				return err
			}
			tk, tv = tc.Next()
		default: // key in both
			if err := visit(bk, bv, tv); err != nil {
				return err
			}
			bk, bv = bc.Next()
			tk, tv = tc.Next()
		}
	}
	return nil
}

// updateDetectionDiff walks two `<ecosystem>/detection` buckets in sorted key
// order and accumulates per-source Detection-related counts into agg,
// including the per-axis criterion split (see SourceDiff). Either bucket
// may be nil. Sources skipped for having zero criterions are counted in
// skipped.
func updateDetectionDiff(bDet, tDet *bolt.Bucket, agg map[sourceTypes.SourceID]SourceDiff, skipped map[sourceTypes.SourceID]int) error {
	err := mergeBuckets(bDet, tDet, func(k, bv, tv []byte) error {
		switch {
		case tv == nil: // baseline-only → Removed
			counts, err := countCriterions(bv)
			if err != nil {
				return errors.Wrapf(err, "count criterions for baseline. root ID: %s", string(k))
			}
			for sid, count := range counts {
				if count == 0 {
					// A source with zero criterions can never match — an
					// extraction bug; skip it (it exists in shipped data,
					// e.g. fedora-api advisories without packages). The
					// caller reports the skips in one aggregated warning
					// per source.
					skipped[sid]++
					continue
				}
				sd := agg[sid]
				sd.BaselineKeys++
				sd.Removed = append(sd.Removed, string(k))
				sd.BaselineCriterions += count
				sd.RemovedCriterions += count
				agg[sid] = sd
			}
		case bv == nil: // target-only → Added
			counts, err := countCriterions(tv)
			if err != nil {
				return errors.Wrapf(err, "count criterions for target. root ID: %s", string(k))
			}
			for sid, count := range counts {
				if count == 0 {
					// See the zero-criterion note above.
					skipped[sid]++
					continue
				}
				sd := agg[sid]
				sd.TargetKeys++
				sd.Added = append(sd.Added, string(k))
				sd.TargetCriterions += count
				sd.AddedCriterions += count
				agg[sid] = sd
			}
		default: // key in both → compare per source
			tallies, err := compareCriterions(bv, tv)
			if err != nil {
				return errors.Wrapf(err, "compare criterions for root ID: %s", string(k))
			}
			for sid, t := range tallies {
				if t.Baseline == 0 && t.Target == 0 {
					// Present on at least one side but with zero units on
					// both — see the zero-criterion note above.
					skipped[sid]++
					continue
				}
				sd := agg[sid]
				if t.Baseline > 0 {
					sd.BaselineKeys++
					sd.BaselineCriterions += t.Baseline
				}
				if t.Target > 0 {
					sd.TargetKeys++
					sd.TargetCriterions += t.Target
				}
				sd.MatchedCriterions += t.Matched
				// Pair the unmatched criterions of both sides under this
				// root ID as changed; the surplus is removed (baseline
				// side) or added (target side). The pairing is by count
				// only — which criterion replaced which is not tracked.
				lost, gained := t.Baseline-t.Matched, t.Target-t.Matched
				changed := min(lost, gained)
				sd.ChangedCriterions += changed
				sd.RemovedCriterions += lost - changed
				sd.AddedCriterions += gained - changed
				switch {
				case t.Baseline > 0 && t.Target > 0:
					if t.Matched < t.Baseline || t.Matched < t.Target {
						sd.Changed = append(sd.Changed, string(k))
					}
				case t.Baseline > 0:
					sd.Removed = append(sd.Removed, string(k))
				case t.Target > 0:
					sd.Added = append(sd.Added, string(k))
				}
				agg[sid] = sd
			}
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(err, "merge detection buckets")
	}
	return nil
}

// updateKBDiff walks two `<ecosystem>/kb` buckets in sorted key order and
// accumulates per-source KB-related counts into agg. Either bucket may be
// nil.
func updateKBDiff(bKB, tKB *bolt.Bucket, agg map[sourceTypes.SourceID]SourceDiff) error {
	err := mergeBuckets(bKB, tKB, func(k, bv, tv []byte) error {
		switch {
		case tv == nil: // baseline-only → Removed
			sids, err := kbSources(bv)
			if err != nil {
				return errors.Wrapf(err, "collect KB sources for baseline. KB ID: %s", string(k))
			}
			for _, sid := range sids {
				sd := agg[sid]
				sd.BaselineKBKeys++
				sd.RemovedKBs = append(sd.RemovedKBs, string(k))
				agg[sid] = sd
			}
		case bv == nil: // target-only → Added
			sids, err := kbSources(tv)
			if err != nil {
				return errors.Wrapf(err, "collect KB sources for target. KB ID: %s", string(k))
			}
			for _, sid := range sids {
				sd := agg[sid]
				sd.TargetKBKeys++
				sd.AddedKBs = append(sd.AddedKBs, string(k))
				agg[sid] = sd
			}
		default: // key in both → compare per source
			tallies, err := compareKBs(bv, tv)
			if err != nil {
				return errors.Wrapf(err, "compare KBs for KB ID: %s", string(k))
			}
			for sid, t := range tallies {
				sd := agg[sid]
				if t.Baseline > 0 {
					sd.BaselineKBKeys++
				}
				if t.Target > 0 {
					sd.TargetKBKeys++
				}
				sd.MatchedKBs += t.Matched
				switch {
				case t.Baseline > 0 && t.Target > 0:
					if t.Matched < t.Baseline || t.Matched < t.Target {
						sd.ChangedKBs = append(sd.ChangedKBs, string(k))
					}
				case t.Baseline > 0:
					sd.RemovedKBs = append(sd.RemovedKBs, string(k))
				case t.Target > 0:
					sd.AddedKBs = append(sd.AddedKBs, string(k))
				}
				agg[sid] = sd
			}
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(err, "merge kb buckets")
	}
	return nil
}

// tally tallies the units of a single key compared between baseline and
// target, for one source. A unit is the smallest compared element feeding
// the change rate: a leaf criterion (with its operator path) for the
// detection bucket, and a per-source KB record (0/1 per KB ID) for the kb
// bucket. A non-zero count doubles as presence: a source that appears in a
// value map with zero units cannot ever match — an extraction bug (e.g.
// fedora-api advisories without packages) — and is skipped with a warning
// by the accumulation sites, so Baseline > 0 effectively means the source
// is present and usable in baseline (likewise for Target).
type tally struct {
	Baseline int
	Target   int
	Matched  int
}

// compareCriterions structurally compares detection data at the Criterion (leaf) level,
// per data source. It flattens the criteria tree in each condition to extract
// all criterions, then uses Sort + Compare merge-join to count how many
// baseline criterions have an identical match in the target.
//
// The comparison is structural, not semantic: each leaf criterion is annotated
// with the operator path from the root Criteria down to its parent, so
// structurally different but semantically equivalent trees
// (e.g., AND(A, B, C) vs AND(A, AND(B, C))) are treated as distinct.
// This is intentional — the vuls-data-update extractor produces a deterministic
// tree structure for a given data source version, so structural changes always
// indicate an upstream data change worth surfacing.
//
// Returns a per-source tally over the union of source IDs in both sides, so
// new/removed sources contribute to their own change rate.
func compareCriterions(baselineData, targetData []byte) (map[sourceTypes.SourceID]tally, error) {
	var bm, tm map[sourceTypes.SourceID][]conditionTypes.Condition
	if err := json.Unmarshal(baselineData, &bm); err != nil {
		return nil, errors.Wrap(err, "unmarshal baseline criterions")
	}
	if err := json.Unmarshal(targetData, &tm); err != nil {
		return nil, errors.Wrap(err, "unmarshal target criterions")
	}

	flattenAndSort := func(conds []conditionTypes.Condition) []annotatedCriterion {
		var cns []annotatedCriterion
		for _, c := range conds {
			cns = walkCriteria(c.Criteria, nil, cns)
		}
		for i := range cns {
			cns[i].criterion.Sort()
		}
		slices.SortFunc(cns, compareAnnotated)
		return cns
	}

	tallies := make(map[sourceTypes.SourceID]tally, max(len(bm), len(tm)))
	for sid := range bm {
		tallies[sid] = tally{}
	}
	for sid := range tm {
		tallies[sid] = tally{}
	}

	for sid, t := range tallies {
		bCns := flattenAndSort(bm[sid])
		tCns := flattenAndSort(tm[sid])

		t.Baseline = len(bCns)
		t.Target = len(tCns)

		// Merge-join on sorted annotated criterions
		bi, ti := 0, 0
		for bi < len(bCns) && ti < len(tCns) {
			switch cr := compareAnnotated(bCns[bi], tCns[ti]); cr {
			case -1:
				bi++
			case +1:
				ti++
			case 0:
				t.Matched++
				bi++
				ti++
			default:
				return nil, errors.Errorf("unexpected compare result. expected: %v, actual: %d", []int{-1, 0, +1}, cr)
			}
		}
		tallies[sid] = t
	}
	return tallies, nil
}

// annotatedCriterion pairs a leaf Criterion with the operator path from the
// root Criteria down to its immediate parent.  Two criterions that differ only
// in their operator context are considered distinct.
type annotatedCriterion struct {
	criterion criterionTypes.Criterion
	operators []criteriaTypes.CriteriaOperatorType
}

// compareAnnotated compares two annotatedCriterions: first by criterion, then
// by the operator path.
func compareAnnotated(a, b annotatedCriterion) int {
	return cmp.Or(
		criterionTypes.Compare(a.criterion, b.criterion),
		slices.Compare(a.operators, b.operators),
	)
}

// walkCriteria recursively collects leaf Criterions from the criteria tree,
// annotating each with the operator path from the root to the current node.
func walkCriteria(c criteriaTypes.Criteria, opPath []criteriaTypes.CriteriaOperatorType, out []annotatedCriterion) []annotatedCriterion {
	cur := append(slices.Clone(opPath), c.Operator)
	for _, cr := range c.Criterions {
		out = append(out, annotatedCriterion{criterion: cr, operators: cur})
	}
	for _, sub := range c.Criterias {
		out = walkCriteria(sub, cur, out)
	}
	return out
}

// countCriterions unmarshals detection data and returns the leaf criterion
// count per source. Every source ID present in the value map appears as a
// key, even with a zero count — callers skip zero-count sources with a
// warning (see updateDetectionDiff). A zero-length value is an error: the
// writer always stores marshaled JSON and reads elsewhere treat empty as
// not-found, so silently skipping it here would let the guard pass over
// corrupt data.
func countCriterions(data []byte) (map[sourceTypes.SourceID]int, error) {
	if len(data) == 0 {
		return nil, errors.New("unexpected zero-length detection value")
	}
	var m map[sourceTypes.SourceID][]conditionTypes.Condition
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, errors.Wrap(err, "unmarshal detection data")
	}
	ns := make(map[sourceTypes.SourceID]int, len(m))
	for sid, conds := range m {
		n := 0
		for _, c := range conds {
			n += countLeafCriterions(c.Criteria)
		}
		ns[sid] = n
	}
	return ns, nil
}

// countLeafCriterions recursively counts leaf Criterions in the criteria tree.
func countLeafCriterions(c criteriaTypes.Criteria) int {
	n := len(c.Criterions)
	for _, sub := range c.Criterias {
		n += countLeafCriterions(sub)
	}
	return n
}

// compareKBs structurally compares KB data per data source. The input bytes
// are the marshaled value of `<ecosystem>/kb/<KB ID>`, i.e. a
// map[sourceTypes.SourceID]microsoftkbTypes.KB. Per-source tallies are 0/1
// per KB ID.
func compareKBs(baselineData, targetData []byte) (map[sourceTypes.SourceID]tally, error) {
	var bm, tm map[sourceTypes.SourceID]microsoftkbTypes.KB
	if err := json.Unmarshal(baselineData, &bm); err != nil {
		return nil, errors.Wrap(err, "unmarshal baseline KBs")
	}
	if err := json.Unmarshal(targetData, &tm); err != nil {
		return nil, errors.Wrap(err, "unmarshal target KBs")
	}

	tallies := make(map[sourceTypes.SourceID]tally, max(len(bm), len(tm)))
	for sid, bKB := range bm {
		t := tally{Baseline: 1}
		if tKB, ok := tm[sid]; ok {
			bKB.Sort()
			tKB.Sort()
			if microsoftkbTypes.Compare(bKB, tKB) == 0 {
				t.Matched = 1
			}
		}
		tallies[sid] = t
	}
	for sid := range tm {
		t := tallies[sid]
		t.Target = 1
		tallies[sid] = t
	}
	return tallies, nil
}

// kbSources unmarshals KB data and returns the source IDs present in the
// value map — a source stores at most one KB record per KB ID, so only the
// key set is meaningful. A zero-length value is an error for the same reason
// as in countCriterions.
func kbSources(data []byte) ([]sourceTypes.SourceID, error) {
	if len(data) == 0 {
		return nil, errors.New("unexpected zero-length KB value")
	}
	var m map[sourceTypes.SourceID]microsoftkbTypes.KB
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, errors.Wrap(err, "unmarshal KB data")
	}
	return slices.Collect(maps.Keys(m)), nil
}
