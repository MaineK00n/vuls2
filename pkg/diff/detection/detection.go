package detection

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

type options struct {
	changeRateThreshold          float64
	changeRateThresholdOverrides map[string]float64
	debug                        bool
	writer                       io.Writer
	detectFunc                   func(baselineBin, baselineDB, targetBin, targetDB string, files map[string]string) (map[string]cveIDs, error)
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
// threshold. Keys are either a scan-result file basename (without the `.json`
// extension, e.g. "debian_13"), which applies to every data source detected
// in that file, or "<file>/<source ID>" (e.g. "cpe_jvn/jvn-feed-rss"), which
// applies to a single source and takes precedence over the file-wide key —
// the same source ID vocabulary `vuls diff db` overrides use. Values are
// percentages. Missing keys fall back to the default supplied via
// WithChangeRateThreshold. A nil or empty map preserves prior behavior.
func WithChangeRateThresholdOverrides(m map[string]float64) Option {
	return changeRateThresholdOverridesOption(m)
}

type debugOption bool

func (o debugOption) apply(opts *options) {
	opts.debug = bool(o)
}

func WithDebug(d bool) Option {
	return debugOption(d)
}

type writerOption struct{ w io.Writer }

func (o writerOption) apply(opts *options) {
	opts.writer = o.w
}

func WithWriter(w io.Writer) Option {
	return writerOption{w: w}
}

// SourceDiff holds the comparison result for a single data source within a
// scan result file. Comparing per source prevents a large source (e.g. NVD in
// a cpe fixture, whose CPE configurations also cover cisco/fortinet products)
// from masking the disappearance of a small source's detections when only the
// union of CVE IDs is compared.
type SourceDiff struct {
	SourceID    sourceTypes.SourceID
	BaselineIDs []string
	TargetIDs   []string
	Added       []string
	Removed     []string
	ChangeRate  float64

	// Threshold actually applied to this (file, source) pair (post override
	// resolution: "<file>/<source>" > "<file>" > default).
	Threshold float64

	Pass bool
}

// FileDiff holds the comparison result for a single scan result file, broken
// down per data source. A file Passes only when every source passes.
type FileDiff struct {
	Name string

	// Per-source diffs computed by diffDetection, in no particular order;
	// the report sorts for presentation.
	Sources []SourceDiff

	Pass bool
}

// cveIDs carries the raw per-source CVE ID collections of one scan result
// file between the collection phase (two vuls0 runs) and diffDetection,
// which reorganizes them into per-source SourceDiff entries.
type cveIDs struct {
	Baseline map[sourceTypes.SourceID][]string
	Target   map[sourceTypes.SourceID][]string
}

// Diff compares detection results between baseline and target pairs of (binary, DB).
func Diff(scanResultsDir, baselineDB, baselineBin, targetDB, targetBin string, opts ...Option) error {
	o := &options{
		changeRateThreshold: 0,
		writer:              os.Stdout,
		detectFunc:          detectAll,
	}
	for _, opt := range opts {
		opt.apply(o)
	}

	if o.debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})))
	}

	files, err := listScanResults(scanResultsDir)
	if err != nil {
		return errors.Wrap(err, "list scan result files")
	}

	slog.Info("Starting detection diff",
		"files", len(files),
		"baseline-binary", baselineBin, "baseline-db", baselineDB,
		"target-binary", targetBin, "target-db", targetDB)

	idm, err := o.detectFunc(baselineBin, baselineDB, targetBin, targetDB, files)
	if err != nil {
		return errors.Wrap(err, "detect")
	}

	diffm := make(map[string]FileDiff, len(idm))
	for name, ids := range idm {
		diffm[name] = diffDetection(name, ids, o.changeRateThresholdOverrides, o.changeRateThreshold)
	}

	pass, err := generateReport(o.writer, diffm)
	if err != nil {
		return errors.Wrap(err, "generate report")
	}
	if !pass {
		// Resolved per-(file, source) threshold is rendered per row in the
		// report's Threshold column, so the exit error stays threshold-free to
		// avoid implying the default was the one that tripped.
		return errors.New("diff failed: change rate exceeded the applicable threshold for at least one (scan-result file, data source); see report for details")
	}
	return nil
}

// resolveThreshold resolves the change-rate threshold for one (file, source)
// pair. Precedence: "<file>/<source>" override > "<file>" override > default.
func resolveThreshold(overrides map[string]float64, def float64, name string, sid sourceTypes.SourceID) float64 {
	if v, ok := overrides[fmt.Sprintf("%s/%s", name, sid)]; ok {
		return v
	}
	if v, ok := overrides[name]; ok {
		return v
	}
	return def
}

// listScanResults lists *.json files in the directory.
// Returns a map from file name (without .json extension) to full path.
func listScanResults(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "read dir %s", dir)
	}
	files := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		files[name] = filepath.Join(dir, e.Name())
	}
	if len(files) == 0 {
		return nil, errors.Errorf("no *.json files found in %s", dir)
	}
	return files, nil
}

// detectAll runs vuls0 detection for all scan result files against both
// baseline and target (binary, DB) pairs in a single worker pool.
func detectAll(baselineBin, baselineDB, targetBin, targetDB string, files map[string]string) (map[string]cveIDs, error) {
	type task struct {
		role   string
		name   string
		binary string
		dbpath string
		path   string
	}

	tasks := make([]task, 0, len(files)*2)
	for name, p := range files {
		tasks = append(tasks,
			task{role: "baseline", name: name, binary: baselineBin, dbpath: baselineDB, path: p},
			task{role: "target", name: name, binary: targetBin, dbpath: targetDB, path: p},
		)
	}

	type result struct {
		role string
		name string
		ids  map[sourceTypes.SourceID][]string
	}

	total := len(tasks)
	resChan := make(chan result, total)

	workers := min(runtime.NumCPU(), total)
	slog.Info("Starting vuls0 detection", "files", len(files), "tasks", total, "workers", workers)

	g, ctx := errgroup.WithContext(context.TODO())
	g.SetLimit(workers)

	for _, t := range tasks {
		g.Go(func() error {
			slog.Debug("vuls0 detect start", "role", t.role, "name", t.name)

			ids, err := runVuls0Report(ctx, t.binary, t.dbpath, t.path)
			if err != nil {
				return errors.Wrapf(err, "vuls0 report %s/%s", t.role, t.name)
			}
			resChan <- result{role: t.role, name: t.name, ids: ids}
			slog.Debug("vuls0 detect done", "role", t.role, "name", t.name, "sources", len(ids))
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, errors.Wrap(err, "vuls0 detection")
	}
	close(resChan)

	idm := make(map[string]cveIDs, len(files))
	for r := range resChan {
		ids := idm[r.name]
		switch r.role {
		case "baseline":
			ids.Baseline = r.ids
		case "target":
			ids.Target = r.ids
		}
		idm[r.name] = ids
	}

	return idm, nil
}

// vulnInfo is the minimal projection of a vuls0 models.VulnInfo needed to
// attribute a detected CVE to the vuls2 data sources that detected it.
type vulnInfo struct {
	CveContents map[string][]cveContent `json:"cveContents"`
}

type cveContent struct {
	Optional map[string]string `json:"optional"`
}

// vuls2Source mirrors the elements of the JSON array vuls0 stores in
// CveContent.Optional["vuls2-sources"] (detector/vuls2's `source` struct);
// only the source ID is needed here.
type vuls2Source struct {
	SourceID sourceTypes.SourceID `json:"source_id"`
}

// runVuls0Report runs vuls0 report on a single scan result file and returns
// detected CVE IDs grouped by data source.
func runVuls0Report(ctx context.Context, binary, dbpath, scanResultPath string) (map[sourceTypes.SourceID][]string, error) {
	tmpDir, err := os.MkdirTemp("", "diff-vuls0-*")
	if err != nil {
		return nil, errors.Wrap(err, "mkdtemp")
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck

	// NOTE: Only [vuls2] is configured; legacy data sources (gost, go-cve-dictionary,
	// etc.) are not included. Detections from legacy sources will not appear in either
	// baseline or target runs.
	if err := os.WriteFile(filepath.Join(tmpDir, "config.toml"), fmt.Appendf(nil,
		`
[servers]
[servers.localhost]
host = "localhost"

[vuls2]
path = %q
skipUpdate = true
`, dbpath), 0o644); err != nil {
		return nil, errors.Wrapf(err, "write config %s", filepath.Join(tmpDir, "config.toml"))
	}

	tsDir := filepath.Join(tmpDir, "results", "2000-01-01T00-00-00+0000")
	if err := os.MkdirAll(tsDir, 0o755); err != nil {
		return nil, errors.Wrapf(err, "mkdir %s", tsDir)
	}

	dst := filepath.Join(tsDir, filepath.Base(scanResultPath))
	if err := func() error {
		in, err := os.Open(scanResultPath)
		if err != nil {
			return errors.Wrapf(err, "open %s", scanResultPath)
		}
		defer in.Close()

		out, err := os.Create(dst)
		if err != nil {
			return errors.Wrapf(err, "create %s", dst)
		}
		defer out.Close()

		if _, err := io.Copy(out, in); err != nil {
			return errors.Wrapf(err, "copy %s to %s", scanResultPath, dst)
		}
		return nil
	}(); err != nil {
		return nil, errors.Wrap(err, "copy scan result file")
	}

	cmd := exec.CommandContext(ctx, binary,
		"report",
		"-config", filepath.Join(tmpDir, "config.toml"),
		"-results-dir", filepath.Join(tmpDir, "results"),
		"-refresh-cve",
		"-format-one-line-text",
		"2000-01-01T00-00-00+0000",
	)
	cmd.Dir = tmpDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, errors.Wrapf(err, "vuls0 report: %s", output)
	}

	f, err := os.Open(dst)
	if err != nil {
		return nil, errors.Wrapf(err, "open %s", dst)
	}
	defer f.Close()

	var sr struct {
		ScannedCves map[string]vulnInfo `json:"scannedCves"`
	}
	if err := json.UnmarshalRead(f, &sr); err != nil {
		return nil, errors.Wrapf(err, "decode %s", dst)
	}

	return collectSources(sr.ScannedCves)
}

// collectSources groups detected CVE IDs by the vuls2 data source that
// detected them, read from CveContent.Optional["vuls2-sources"] — a marker
// only vuls0's vuls2 detection paths attach (enrichment-added CveContents
// never carry it), holding the exact source IDs. This keeps sources the
// coarser confidences[].detectionMethod signal cannot separate (e.g.
// fortinet-csaf vs fortinet-cvrf) distinct, and aligns the override key
// vocabulary with `vuls diff db`. A CVE detected by multiple sources is
// counted under each. Anything that breaks source attribution is an error
// rather than a silent fallback: a marker that is present but unusable (bad
// JSON, empty list, entry without a source_id) signals a marker format
// change, and a detected CVE with no marked content at all signals a vuls0
// bug — with a [vuls2]-only config every detected CVE comes from a vuls2
// detection path, which always attaches the marker.
// ID lists carry no order guarantee; the report sorts for presentation.
func collectSources(scannedCves map[string]vulnInfo) (map[sourceTypes.SourceID][]string, error) {
	m := make(map[sourceTypes.SourceID][]string)
	for cve, vi := range scannedCves {
		sources := make(map[sourceTypes.SourceID]struct{})
		for _, contents := range vi.CveContents {
			for _, c := range contents {
				raw, ok := c.Optional["vuls2-sources"]
				if !ok {
					continue
				}
				var ss []vuls2Source
				if err := json.Unmarshal([]byte(raw), &ss); err != nil {
					return nil, errors.Wrapf(err, "unmarshal vuls2-sources of %s", cve)
				}
				if len(ss) == 0 {
					return nil, errors.Errorf("unexpected empty vuls2-sources of %s", cve)
				}
				for _, s := range ss {
					if s.SourceID == "" {
						return nil, errors.Errorf("unexpected vuls2-sources entry without source_id of %s", cve)
					}
					sources[s.SourceID] = struct{}{}
				}
			}
		}
		if len(sources) == 0 {
			return nil, errors.Errorf("no vuls2-sources marker on any content of %s", cve)
		}
		for s := range sources {
			m[s] = append(m[s], cve)
		}
	}
	return m, nil
}

// diffDetection builds the FileDiff of one scan result file from its raw
// per-source CVE ID collections. Per-source thresholds are resolved from
// overrides via resolveThreshold, falling back to threshold. Parallels
// `diffEcosystem` on the db side.
//
// Only (CVE ID, source) pairs are compared; per-CVE content (confidence
// score, affected packages, CVSS, exploit/KEV metadata, etc.) is not diffed.
// Content-only changes are therefore invisible. This is sufficient for
// regression detection (missing or extra CVEs per data source), but not for
// validating data source migrations where IDs stay the same but metadata
// differs.
func diffDetection(name string, ids cveIDs, overrides map[string]float64, threshold float64) FileDiff {
	sources := make(map[sourceTypes.SourceID]struct{})
	for s := range ids.Baseline {
		sources[s] = struct{}{}
	}
	for s := range ids.Target {
		sources[s] = struct{}{}
	}

	d := FileDiff{
		Name:    name,
		Sources: make([]SourceDiff, 0, len(sources)),
	}
	for sid := range sources {
		sd := SourceDiff{
			SourceID:    sid,
			BaselineIDs: ids.Baseline[sid],
			TargetIDs:   ids.Target[sid],
		}
		sd.Added = subtract(sd.TargetIDs, sd.BaselineIDs)
		sd.Removed = subtract(sd.BaselineIDs, sd.TargetIDs)
		sd.ChangeRate = changeRate(len(sd.BaselineIDs), len(sd.Added), len(sd.Removed))
		sd.Threshold = resolveThreshold(overrides, threshold, name, sid)
		sd.Pass = sd.ChangeRate <= sd.Threshold
		d.Sources = append(d.Sources, sd)
	}
	d.Pass = !slices.ContainsFunc(d.Sources, func(sd SourceDiff) bool { return !sd.Pass })
	return d
}

// changeRate computes a per-source change rate as a percentage:
//
//	(added + removed) / baseline * 100
//
// It can exceed 100% when additions outnumber baseline entries — capping at
// 100 would hide the magnitude of large additions. When baseline is empty but
// entries were added or removed, the rate is 100. When nothing changed, 0.
func changeRate(baseline, added, removed int) float64 {
	switch {
	case baseline > 0:
		return float64(added+removed) / float64(baseline) * 100
	case added+removed > 0:
		return 100
	default:
		return 0
	}
}

// subtract returns elements in a that are not in b (i.e. a \ b).
func subtract(a, b []string) []string {
	bSet := make(map[string]struct{}, len(b))
	for _, v := range b {
		bSet[v] = struct{}{}
	}
	var diff []string
	for _, v := range a {
		if _, ok := bSet[v]; !ok {
			diff = append(diff, v)
		}
	}
	return diff
}
