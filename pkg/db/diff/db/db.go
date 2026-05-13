package db

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/v2"
	"io"
	"log/slog"
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

// WithChangeRateThresholdOverrides supplies per-ecosystem overrides of the
// change rate threshold. Keys are ecosystem identifiers (e.g. "ubuntu:26.04");
// values are percentages. Missing keys fall back to the default supplied via
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

// EcosystemDiff holds the comparison result for a single ecosystem.
//
// An ecosystem bucket may contain a `detection` sub-bucket, a `kb` sub-bucket,
// or both. Each sub-bucket is diffed independently and has its own change
// rate so that disparities in magnitude (e.g. many detection units vs few KB
// units) do not hide a large relative change in the smaller bucket.
// An ecosystem Passes only when both change rates are within the threshold.
type EcosystemDiff struct {
	Ecosystem ecosystemTypes.Ecosystem

	// Detection bucket diff (`<ecosystem>/detection/<Root ID>`).
	BaselineKeys       int
	TargetKeys         int
	Added              []string // root IDs in target but not baseline
	Removed            []string // root IDs in baseline but not target
	Changed            []string // root IDs in both but different detection data
	BaselineCriterions int      // total leaf criterion count across all baseline root IDs
	TargetCriterions   int      // total leaf criterion count across all target root IDs
	MatchedCriterions  int      // criterions structurally identical in both (Sort + Compare == 0)

	// KB bucket diff (`<ecosystem>/kb/<KB ID>`).
	BaselineKBKeys int
	TargetKBKeys   int
	AddedKBs       []string // KB IDs in target but not baseline
	RemovedKBs     []string // KB IDs in baseline but not target
	ChangedKBs     []string // KB IDs in both but different KB data
	BaselineKBs    int      // total (KB ID × source ID) pair count in baseline
	TargetKBs      int      // total (KB ID × source ID) pair count in target
	MatchedKBs     int      // KB pairs structurally identical in both (Sort + Compare == 0)

	// Per-bucket change rates. When a bucket is absent in both baseline
	// and target, its rate is 0.
	DetectionChangeRate float64
	KBChangeRate        float64

	// Threshold actually applied to this ecosystem (post override resolution).
	// ThresholdOverridden is true iff a per-ecosystem override matched.
	Threshold           float64
	ThresholdOverridden bool

	Pass bool
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

	pass, err := generateReport(o.writer, results, o.changeRateThreshold)
	if err != nil {
		return errors.Wrap(err, "generate report")
	}

	if !pass {
		// Resolved per-ecosystem threshold (default vs override) is rendered in
		// the report's Override column, so the exit error stays threshold-free
		// to avoid implying the default was the one that tripped.
		return errors.New("diff failed: detection and/or KB change rate exceeded the applicable threshold for at least one ecosystem; see report for details")
	}
	return nil
}

// resolveThreshold returns the threshold to apply to a given ecosystem,
// preferring an override entry when present. The second return value reports
// whether the override map matched.
func resolveThreshold(key string, def float64, overrides map[string]float64) (float64, bool) {
	if v, ok := overrides[key]; ok {
		return v, true
	}
	return def, false
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

			d, err := diffEcosystem(baselineDB, targetDB, eco, changeRateThreshold, overrides)
			if err != nil {
				return errors.Wrapf(err, "diff ecosystem %s", string(eco))
			}

			slog.Debug("ecosystem diff done",
				"ecosystem", eco, "pass", d.Pass,
				"detection_change_rate", d.DetectionChangeRate, "target_criterions", d.TargetCriterions,
				"kb_change_rate", d.KBChangeRate, "target_kbs", d.TargetKBs)
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
			case "metadata", "vulnerability", "datasource":
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
// sub-buckets (detection, kb) independently. Either sub-bucket may be absent.
func diffEcosystem(baselineDB, targetDB *bolt.DB, ecosystem ecosystemTypes.Ecosystem, changeRateThreshold float64, overrides map[string]float64) (EcosystemDiff, error) {
	diff := EcosystemDiff{Ecosystem: ecosystem}

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
			if err := updateDetectionDiff(bDet, tDet, &diff); err != nil {
				return errors.Wrap(err, "diff detection bucket")
			}

			var bKB, tKB *bolt.Bucket
			if bEco != nil {
				bKB = bEco.Bucket([]byte("kb"))
			}
			if tEco != nil {
				tKB = tEco.Bucket([]byte("kb"))
			}
			if err := updateKBDiff(bKB, tKB, &diff); err != nil {
				return errors.Wrap(err, "diff kb bucket")
			}

			return nil
		})
	}); err != nil {
		return EcosystemDiff{}, errors.Wrap(err, "diff ecosystem")
	}

	diff.DetectionChangeRate = changeRate(diff.BaselineCriterions, diff.TargetCriterions, diff.MatchedCriterions)
	diff.KBChangeRate = changeRate(diff.BaselineKBs, diff.TargetKBs, diff.MatchedKBs)
	diff.Threshold, diff.ThresholdOverridden = resolveThreshold(string(ecosystem), changeRateThreshold, overrides)
	diff.Pass = diff.DetectionChangeRate <= diff.Threshold && diff.KBChangeRate <= diff.Threshold
	return diff, nil
}

// updateDetectionDiff merge-joins two `<ecosystem>/detection` buckets on sorted
// cursors and fills the Detection-related fields of diff. Either bucket may
// be nil.
func updateDetectionDiff(bDet, tDet *bolt.Bucket, diff *EcosystemDiff) error {
	if bDet == nil && tDet == nil {
		return nil
	}

	if bDet == nil {
		return tDet.ForEach(func(k, v []byte) error {
			diff.TargetKeys++
			diff.Added = append(diff.Added, string(k))
			n, err := countCriterions(v)
			if err != nil {
				return errors.Wrapf(err, "count criterions for target. root ID: %s", string(k))
			}
			diff.TargetCriterions += n
			return nil
		})
	}

	if tDet == nil {
		return bDet.ForEach(func(k, v []byte) error {
			diff.BaselineKeys++
			diff.Removed = append(diff.Removed, string(k))
			n, err := countCriterions(v)
			if err != nil {
				return errors.Wrapf(err, "count criterions for baseline. root ID: %s", string(k))
			}
			diff.BaselineCriterions += n
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
			diff.BaselineKeys++
			diff.Removed = append(diff.Removed, string(bk))
			n, err := countCriterions(bv)
			if err != nil {
				return errors.Wrapf(err, "count criterions for baseline. root ID: %s", string(bk))
			}
			diff.BaselineCriterions += n
			bk, bv = bc.Next()
		case +1: // target-only → Added
			diff.TargetKeys++
			diff.Added = append(diff.Added, string(tk))
			n, err := countCriterions(tv)
			if err != nil {
				return errors.Wrapf(err, "count criterions for target. root ID: %s", string(tk))
			}
			diff.TargetCriterions += n
			tk, tv = tc.Next()
		case 0: // both present → compare
			diff.BaselineKeys++
			diff.TargetKeys++
			base, target, matched, err := compareCriterions(bv, tv)
			if err != nil {
				return errors.Wrapf(err, "compare criterions for root ID: %s", string(bk))
			}
			diff.BaselineCriterions += base
			diff.TargetCriterions += target
			diff.MatchedCriterions += matched
			if matched < base || matched < target {
				diff.Changed = append(diff.Changed, string(bk))
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
// fills the KB-related fields of diff. Either bucket may be nil.
func updateKBDiff(bKB, tKB *bolt.Bucket, diff *EcosystemDiff) error {
	if bKB == nil && tKB == nil {
		return nil
	}

	if bKB == nil {
		return tKB.ForEach(func(k, v []byte) error {
			diff.TargetKBKeys++
			diff.AddedKBs = append(diff.AddedKBs, string(k))
			n, err := countKBs(v)
			if err != nil {
				return errors.Wrapf(err, "count KBs for target. KB ID: %s", string(k))
			}
			diff.TargetKBs += n
			return nil
		})
	}

	if tKB == nil {
		return bKB.ForEach(func(k, v []byte) error {
			diff.BaselineKBKeys++
			diff.RemovedKBs = append(diff.RemovedKBs, string(k))
			n, err := countKBs(v)
			if err != nil {
				return errors.Wrapf(err, "count KBs for baseline. KB ID: %s", string(k))
			}
			diff.BaselineKBs += n
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
			diff.BaselineKBKeys++
			diff.RemovedKBs = append(diff.RemovedKBs, string(bk))
			n, err := countKBs(bv)
			if err != nil {
				return errors.Wrapf(err, "count KBs for baseline. KB ID: %s", string(bk))
			}
			diff.BaselineKBs += n
			bk, bv = bc.Next()
		case +1:
			diff.TargetKBKeys++
			diff.AddedKBs = append(diff.AddedKBs, string(tk))
			n, err := countKBs(tv)
			if err != nil {
				return errors.Wrapf(err, "count KBs for target. KB ID: %s", string(tk))
			}
			diff.TargetKBs += n
			tk, tv = tc.Next()
		case 0:
			diff.BaselineKBKeys++
			diff.TargetKBKeys++
			base, target, matched, err := compareKBs(bv, tv)
			if err != nil {
				return errors.Wrapf(err, "compare KBs for KB ID: %s", string(bk))
			}
			diff.BaselineKBs += base
			diff.TargetKBs += target
			diff.MatchedKBs += matched
			if matched < base || matched < target {
				diff.ChangedKBs = append(diff.ChangedKBs, string(bk))
			}
			bk, bv = bc.Next()
			tk, tv = tc.Next()
		default:
			return errors.Errorf("unexpected compare result. expected: %v, actual: %d", []int{-1, 0, +1}, c)
		}
	}

	return nil
}

// compareCriterions structurally compares detection data at the Criterion (leaf) level.
// It flattens the criteria tree in each condition to extract all criterions,
// then uses Sort + Compare merge-join to count how many baseline criterions
// have an identical match in the target.
//
// The comparison is structural, not semantic: each leaf criterion is annotated
// with the operator path from the root Criteria down to its parent, so
// structurally different but semantically equivalent trees
// (e.g., AND(A, B, C) vs AND(A, AND(B, C))) are treated as distinct.
// This is intentional — the vuls-data-update extractor produces a deterministic
// tree structure for a given data source version, so structural changes always
// indicate an upstream data change worth surfacing.
//
// Returns (baselineCount, targetCount, matchedCount).
func compareCriterions(baselineData, targetData []byte) (baseline, target, matched int, _ error) {
	var bm, tm map[sourceTypes.SourceID][]conditionTypes.Condition
	if err := json.Unmarshal(baselineData, &bm); err != nil {
		return 0, 0, 0, errors.Wrap(err, "unmarshal baseline criterions")
	}
	if err := json.Unmarshal(targetData, &tm); err != nil {
		return 0, 0, 0, errors.Wrap(err, "unmarshal target criterions")
	}

	// Iterate over union of source IDs so new/removed sources contribute to change rate.
	srcs := make(map[sourceTypes.SourceID]struct{}, len(bm))
	for src := range bm {
		srcs[src] = struct{}{}
	}
	for src := range tm {
		srcs[src] = struct{}{}
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

	for src := range srcs {
		bCns := flattenAndSort(bm[src])
		tCns := flattenAndSort(tm[src])

		baseline += len(bCns)
		target += len(tCns)

		// Merge-join on sorted annotated criterions
		bi, ti := 0, 0
		for bi < len(bCns) && ti < len(tCns) {
			switch c := compareAnnotated(bCns[bi], tCns[ti]); c {
			case -1:
				bi++
			case +1:
				ti++
			case 0:
				matched++
				bi++
				ti++
			default:
				return 0, 0, 0, errors.Errorf("unexpected compare result. expected: %v, actual: %d", []int{-1, 0, +1}, c)
			}
		}
	}
	return baseline, target, matched, nil
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

// countCriterions unmarshals detection data and returns the total leaf criterion count.
func countCriterions(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	var m map[sourceTypes.SourceID][]conditionTypes.Condition
	if err := json.Unmarshal(data, &m); err != nil {
		return 0, errors.Wrap(err, "unmarshal detection data")
	}
	n := 0
	for _, conds := range m {
		for _, c := range conds {
			n += countLeafCriterions(c.Criteria)
		}
	}
	return n, nil
}

// countLeafCriterions recursively counts leaf Criterions in the criteria tree.
func countLeafCriterions(c criteriaTypes.Criteria) int {
	n := len(c.Criterions)
	for _, sub := range c.Criterias {
		n += countLeafCriterions(sub)
	}
	return n
}

// compareKBs structurally compares KB data at the (KB ID × source ID) pair level.
// The input bytes are the marshaled value of `<ecosystem>/kb/<KB ID>`, i.e. a
// map[sourceTypes.SourceID]microsoftkbTypes.KB. Returns per-source counts:
// (baselineCount, targetCount, matchedCount).
func compareKBs(baselineData, targetData []byte) (baseline, target, matched int, _ error) {
	var bm, tm map[sourceTypes.SourceID]microsoftkbTypes.KB
	if err := json.Unmarshal(baselineData, &bm); err != nil {
		return 0, 0, 0, errors.Wrap(err, "unmarshal baseline KBs")
	}
	if err := json.Unmarshal(targetData, &tm); err != nil {
		return 0, 0, 0, errors.Wrap(err, "unmarshal target KBs")
	}

	baseline = len(bm)
	target = len(tm)

	for src, bKB := range bm {
		tKB, ok := tm[src]
		if !ok {
			continue
		}
		bKB.Sort()
		tKB.Sort()
		if microsoftkbTypes.Compare(bKB, tKB) == 0 {
			matched++
		}
	}
	return baseline, target, matched, nil
}

// countKBs unmarshals KB data and returns the number of (KB ID × source ID)
// pairs it contributes (i.e. len of the source map).
func countKBs(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	var m map[sourceTypes.SourceID]microsoftkbTypes.KB
	if err := json.Unmarshal(data, &m); err != nil {
		return 0, errors.Wrap(err, "unmarshal KB data")
	}
	return len(m), nil
}
