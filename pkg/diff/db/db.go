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
)

type options struct {
	changeRateThreshold          float64
	changeRateThresholdOverrides map[string]float64
	writer                       io.Writer
	debug                        bool
}

type Option interface {
	apply(*options)
}

type changeRateThresholdOption float64

func (o changeRateThresholdOption) apply(opts *options) {
	opts.changeRateThreshold = float64(o)
}

func WithChangeRateThreshold(r float64) Option {
	return changeRateThresholdOption(r)
}

type changeRateThresholdOverridesOption map[string]float64

func (o changeRateThresholdOverridesOption) apply(opts *options) {
	opts.changeRateThresholdOverrides = map[string]float64(o)
}

// WithChangeRateThresholdOverrides supplies overrides of the change rate
// threshold. Keys are either an ecosystem identifier (e.g. "ubuntu:26.04"),
// which applies to every source in that ecosystem, or
// "<ecosystem>/<source ID>" (e.g. "cpe/cisco-json"), which applies to a
// single source and takes precedence over the ecosystem-wide key. Values are
// percentages. Missing keys fall back to the default supplied via
// WithChangeRateThreshold. A nil or empty map preserves prior behavior.
func WithChangeRateThresholdOverrides(m map[string]float64) Option {
	return changeRateThresholdOverridesOption(m)
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
// both. Each is diffed independently and has its own change rate so that
// disparities in magnitude (e.g. many detection units vs few KB units) do not
// hide a large relative change in the smaller bucket.
// A source Passes only when both change rates are within its threshold.
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

	// Per-bucket change rates. When a bucket is absent in both baseline
	// and target, its rate is 0.
	DetectionChangeRate float64
	KBChangeRate        float64

	// Threshold actually applied to this source (post override resolution:
	// "<ecosystem>/<source>" > "<ecosystem>" > default).
	Threshold float64

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
		changeRateThreshold: 0,
		writer:              os.Stdout,
		debug:               false,
	}
	for _, opt := range opts {
		opt.apply(o)
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

	results, err := computeDiffs(baselineDB, targetDB, o.changeRateThreshold, o.changeRateThresholdOverrides)
	if err != nil {
		return errors.Wrap(err, "compute diffs")
	}

	pass, err := generateReport(o.writer, results)
	if err != nil {
		return errors.Wrap(err, "generate report")
	}

	if !pass {
		// Resolved per-source threshold is rendered per row in the report's
		// Threshold column, so the exit error stays threshold-free to avoid
		// implying the default was the one that tripped.
		return errors.New("diff failed: detection and/or KB change rate exceeded the applicable threshold for at least one (ecosystem, source); see report for details")
	}
	return nil
}

func computeDiffs(baselineDB, targetDB *bolt.DB, changeRateThreshold float64, overrides map[string]float64) ([]EcosystemDiff, error) {
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

			d, err := diffEcosystem(baselineDB, targetDB, eco, overrides, changeRateThreshold)
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

// resolveThreshold resolves the change-rate threshold for one
// (ecosystem, source) pair.
// Precedence: "<ecosystem>/<source>" override > "<ecosystem>" override > default.
func resolveThreshold(overrides map[string]float64, def float64, eco ecosystemTypes.Ecosystem, sid sourceTypes.SourceID) float64 {
	if v, ok := overrides[fmt.Sprintf("%s/%s", eco, sid)]; ok {
		return v
	}
	if v, ok := overrides[string(eco)]; ok {
		return v
	}
	return def
}

// changeRate computes a per-bucket change rate as a percentage:
//
//	(baseline - matched + target - matched) / baseline * 100
//
// When baseline is 0 but target has unmatched units, the rate is 100. When
// both are 0, the rate is 0.
func changeRate(baseline, target, matched int) float64 {
	switch {
	case baseline > 0:
		return float64(baseline-matched+target-matched) / float64(baseline) * 100
	case target-matched > 0:
		return 100
	default:
		return 0
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
// resolved from overrides via resolveThreshold, falling back to threshold.
func diffEcosystem(baselineDB, targetDB *bolt.DB, ecosystem ecosystemTypes.Ecosystem, overrides map[string]float64, threshold float64) (EcosystemDiff, error) {
	diff := EcosystemDiff{Ecosystem: ecosystem}
	agg := make(map[sourceTypes.SourceID]SourceDiff)

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
			if err := updateDetectionDiff(bDet, tDet, agg); err != nil {
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

	diff.Sources = make([]SourceDiff, 0, len(agg))
	for sid, sd := range agg {
		sd.SourceID = sid
		sd.DetectionChangeRate = changeRate(sd.BaselineCriterions, sd.TargetCriterions, sd.MatchedCriterions)
		sd.KBChangeRate = changeRate(sd.BaselineKBKeys, sd.TargetKBKeys, sd.MatchedKBs)
		sd.Threshold = resolveThreshold(overrides, threshold, ecosystem, sid)
		sd.Pass = sd.DetectionChangeRate <= sd.Threshold && sd.KBChangeRate <= sd.Threshold
		diff.Sources = append(diff.Sources, sd)
	}
	diff.Pass = !slices.ContainsFunc(diff.Sources, func(s SourceDiff) bool { return !s.Pass })
	return diff, nil
}

// updateDetectionDiff merge-joins two `<ecosystem>/detection` buckets on sorted
// cursors and accumulates per-source Detection-related counts into agg. Either
// bucket may be nil.
func updateDetectionDiff(bDet, tDet *bolt.Bucket, agg map[sourceTypes.SourceID]SourceDiff) error {
	if bDet == nil && tDet == nil {
		return nil
	}

	if bDet == nil {
		return tDet.ForEach(func(k, v []byte) error {
			counts, err := countCriterions(v)
			if err != nil {
				return errors.Wrapf(err, "count criterions for target. root ID: %s", string(k))
			}
			for sid, count := range counts {
				sd := agg[sid]
				sd.TargetKeys++
				sd.Added = append(sd.Added, string(k))
				sd.TargetCriterions += count
				agg[sid] = sd
			}
			return nil
		})
	}

	if tDet == nil {
		return bDet.ForEach(func(k, v []byte) error {
			counts, err := countCriterions(v)
			if err != nil {
				return errors.Wrapf(err, "count criterions for baseline. root ID: %s", string(k))
			}
			for sid, count := range counts {
				sd := agg[sid]
				sd.BaselineKeys++
				sd.Removed = append(sd.Removed, string(k))
				sd.BaselineCriterions += count
				agg[sid] = sd
			}
			return nil
		})
	}

	// Merge-join: both BoltDB cursors iterate in sorted key order.
	bc := bDet.Cursor()
	tc := tDet.Cursor()

	bk, bv := bc.First()
	tk, tv := tc.First()

	for bk != nil || tk != nil {
		switch c := func() int {
			if bk == nil {
				return +1
			}
			if tk == nil {
				return -1
			}
			return bytes.Compare(bk, tk)
		}(); c {
		case -1: // baseline-only → Removed
			counts, err := countCriterions(bv)
			if err != nil {
				return errors.Wrapf(err, "count criterions for baseline. root ID: %s", string(bk))
			}
			for sid, count := range counts {
				sd := agg[sid]
				sd.BaselineKeys++
				sd.Removed = append(sd.Removed, string(bk))
				sd.BaselineCriterions += count
				agg[sid] = sd
			}
			bk, bv = bc.Next()
		case +1: // target-only → Added
			counts, err := countCriterions(tv)
			if err != nil {
				return errors.Wrapf(err, "count criterions for target. root ID: %s", string(tk))
			}
			for sid, count := range counts {
				sd := agg[sid]
				sd.TargetKeys++
				sd.Added = append(sd.Added, string(tk))
				sd.TargetCriterions += count
				agg[sid] = sd
			}
			tk, tv = tc.Next()
		case 0: // both present → compare per source
			counts, err := compareCriterions(bv, tv)
			if err != nil {
				return errors.Wrapf(err, "compare criterions for root ID: %s", string(bk))
			}
			for sid, count := range counts {
				sd := agg[sid]
				if count.InBaseline {
					sd.BaselineKeys++
					sd.BaselineCriterions += count.Baseline
				}
				if count.InTarget {
					sd.TargetKeys++
					sd.TargetCriterions += count.Target
				}
				sd.MatchedCriterions += count.Matched
				switch {
				case count.InBaseline && count.InTarget:
					if count.Matched < count.Baseline || count.Matched < count.Target {
						sd.Changed = append(sd.Changed, string(bk))
					}
				case count.InBaseline:
					sd.Removed = append(sd.Removed, string(bk))
				case count.InTarget:
					sd.Added = append(sd.Added, string(bk))
				}
				agg[sid] = sd
			}
			bk, bv = bc.Next()
			tk, tv = tc.Next()
		default:
			return errors.Errorf("unexpected compare result. expected: %v, actual: %d", []int{-1, 0, +1}, c)
		}
	}

	return nil
}

// updateKBDiff merge-joins two `<ecosystem>/kb` buckets on sorted cursors and
// accumulates per-source KB-related counts into agg. Either bucket may be nil.
func updateKBDiff(bKB, tKB *bolt.Bucket, agg map[sourceTypes.SourceID]SourceDiff) error {
	if bKB == nil && tKB == nil {
		return nil
	}

	if bKB == nil {
		return tKB.ForEach(func(k, v []byte) error {
			sids, err := kbSources(v)
			if err != nil {
				return errors.Wrapf(err, "collect KB sources for target. KB ID: %s", string(k))
			}
			for _, sid := range sids {
				sd := agg[sid]
				sd.TargetKBKeys++
				sd.AddedKBs = append(sd.AddedKBs, string(k))
				agg[sid] = sd
			}
			return nil
		})
	}

	if tKB == nil {
		return bKB.ForEach(func(k, v []byte) error {
			sids, err := kbSources(v)
			if err != nil {
				return errors.Wrapf(err, "collect KB sources for baseline. KB ID: %s", string(k))
			}
			for _, sid := range sids {
				sd := agg[sid]
				sd.BaselineKBKeys++
				sd.RemovedKBs = append(sd.RemovedKBs, string(k))
				agg[sid] = sd
			}
			return nil
		})
	}

	bc := bKB.Cursor()
	tc := tKB.Cursor()

	bk, bv := bc.First()
	tk, tv := tc.First()

	for bk != nil || tk != nil {
		switch c := func() int {
			if bk == nil {
				return +1
			}
			if tk == nil {
				return -1
			}
			return bytes.Compare(bk, tk)
		}(); c {
		case -1:
			sids, err := kbSources(bv)
			if err != nil {
				return errors.Wrapf(err, "collect KB sources for baseline. KB ID: %s", string(bk))
			}
			for _, sid := range sids {
				sd := agg[sid]
				sd.BaselineKBKeys++
				sd.RemovedKBs = append(sd.RemovedKBs, string(bk))
				agg[sid] = sd
			}
			bk, bv = bc.Next()
		case +1:
			sids, err := kbSources(tv)
			if err != nil {
				return errors.Wrapf(err, "collect KB sources for target. KB ID: %s", string(tk))
			}
			for _, sid := range sids {
				sd := agg[sid]
				sd.TargetKBKeys++
				sd.AddedKBs = append(sd.AddedKBs, string(tk))
				agg[sid] = sd
			}
			tk, tv = tc.Next()
		case 0:
			counts, err := compareKBs(bv, tv)
			if err != nil {
				return errors.Wrapf(err, "compare KBs for KB ID: %s", string(bk))
			}
			for sid, count := range counts {
				sd := agg[sid]
				if count.InBaseline {
					sd.BaselineKBKeys++
				}
				if count.InTarget {
					sd.TargetKBKeys++
				}
				sd.MatchedKBs += count.Matched
				switch {
				case count.InBaseline && count.InTarget:
					if count.Matched < count.Baseline || count.Matched < count.Target {
						sd.ChangedKBs = append(sd.ChangedKBs, string(bk))
					}
				case count.InBaseline:
					sd.RemovedKBs = append(sd.RemovedKBs, string(bk))
				case count.InTarget:
					sd.AddedKBs = append(sd.AddedKBs, string(bk))
				}
				agg[sid] = sd
			}
			bk, bv = bc.Next()
			tk, tv = tc.Next()
		default:
			return errors.Errorf("unexpected compare result. expected: %v, actual: %d", []int{-1, 0, +1}, c)
		}
	}

	return nil
}

// unitCounts holds per-source unit counts for a single key compared between
// baseline and target. InBaseline/InTarget record whether the source appears
// in the corresponding value map at all — a source may be present with zero
// units, which is still presence for Added/Removed/Changed classification.
type unitCounts struct {
	Baseline   int
	Target     int
	Matched    int
	InBaseline bool
	InTarget   bool
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
// Returns per-source counts over the union of source IDs in both sides, so
// new/removed sources contribute to their own change rate.
func compareCriterions(baselineData, targetData []byte) (map[sourceTypes.SourceID]unitCounts, error) {
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

	counts := make(map[sourceTypes.SourceID]unitCounts, max(len(bm), len(tm)))
	for sid := range bm {
		counts[sid] = unitCounts{InBaseline: true}
	}
	for sid := range tm {
		c := counts[sid]
		c.InTarget = true
		counts[sid] = c
	}

	for sid, c := range counts {
		bCns := flattenAndSort(bm[sid])
		tCns := flattenAndSort(tm[sid])

		c.Baseline = len(bCns)
		c.Target = len(tCns)

		// Merge-join on sorted annotated criterions
		bi, ti := 0, 0
		for bi < len(bCns) && ti < len(tCns) {
			switch cr := compareAnnotated(bCns[bi], tCns[ti]); cr {
			case -1:
				bi++
			case +1:
				ti++
			case 0:
				c.Matched++
				bi++
				ti++
			default:
				return nil, errors.Errorf("unexpected compare result. expected: %v, actual: %d", []int{-1, 0, +1}, cr)
			}
		}
		counts[sid] = c
	}
	return counts, nil
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
// count per source. Every source ID present in the value map appears as a key,
// even with a zero count. A zero-length value is an error: the writer always
// stores marshaled JSON and reads elsewhere treat empty as not-found, so
// silently skipping it here would let the guard pass over corrupt data.
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
// map[sourceTypes.SourceID]microsoftkbTypes.KB. Per-source counts are 0/1
// per KB ID.
func compareKBs(baselineData, targetData []byte) (map[sourceTypes.SourceID]unitCounts, error) {
	var bm, tm map[sourceTypes.SourceID]microsoftkbTypes.KB
	if err := json.Unmarshal(baselineData, &bm); err != nil {
		return nil, errors.Wrap(err, "unmarshal baseline KBs")
	}
	if err := json.Unmarshal(targetData, &tm); err != nil {
		return nil, errors.Wrap(err, "unmarshal target KBs")
	}

	counts := make(map[sourceTypes.SourceID]unitCounts, max(len(bm), len(tm)))
	for sid, bKB := range bm {
		c := unitCounts{InBaseline: true, Baseline: 1}
		if tKB, ok := tm[sid]; ok {
			bKB.Sort()
			tKB.Sort()
			if microsoftkbTypes.Compare(bKB, tKB) == 0 {
				c.Matched = 1
			}
		}
		counts[sid] = c
	}
	for sid := range tm {
		c := counts[sid]
		c.InTarget = true
		c.Target = 1
		counts[sid] = c
	}
	return counts, nil
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
