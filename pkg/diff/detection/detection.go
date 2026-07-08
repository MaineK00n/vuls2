package detection

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

type options struct {
	changeRateThreshold          float64
	changeRateThresholdOverrides map[string]float64
	debug                        bool
	writer                       io.Writer
	detectFunc                   func(baselineBin, baselineDB, targetBin, targetDB string, files map[string]string) (map[string]FileDiff, error)
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
// extension, e.g. "debian_13"), which applies to every source family detected
// in that file, or "<file>/<family>" (e.g. "cpe_jvn/Jvn"), which applies to a
// single source family and takes precedence over the file-wide key. Values
// are percentages. Missing keys fall back to the default supplied via
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

// FamilyDiff holds the comparison result for a single source family within a
// scan result file. Comparing per family prevents a large source (e.g. NVD in
// a cpe fixture, whose CPE configurations also cover cisco/fortinet products)
// from masking the disappearance of a small source's detections when only the
// union of CVE IDs is compared.
type FamilyDiff struct {
	Family      string
	BaselineIDs []string
	TargetIDs   []string
	Added       []string
	Removed     []string
	ChangeRate  float64

	// Threshold actually applied to this (file, family) pair (post override
	// resolution: "<file>/<family>" > "<file>" > default).
	Threshold float64

	Pass bool
}

// FileDiff holds the comparison result for a single scan result file, broken
// down per source family. A file Passes only when every family passes.
type FileDiff struct {
	Name string

	// Raw per-family CVE ID collections from the baseline and target runs.
	BaselineIDs map[string][]string
	TargetIDs   map[string][]string

	// Per-family diffs computed by diffDetection, sorted by Family.
	Families []FamilyDiff

	Pass bool
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

	diffm, err := o.detectFunc(baselineBin, baselineDB, targetBin, targetDB, files)
	if err != nil {
		return errors.Wrap(err, "detect")
	}

	for name, d := range diffm {
		// Resolve via the canonical map key, not d.Name — the two should
		// always match in practice but coupling resolution to the key keeps
		// override lookups consistent across the codebase.
		// Precedence: "<file>/<family>" > "<file>" > default.
		resolveThreshold := func(family string) float64 {
			if v, ok := o.changeRateThresholdOverrides[name+"/"+family]; ok {
				return v
			}
			if v, ok := o.changeRateThresholdOverrides[name]; ok {
				return v
			}
			return o.changeRateThreshold
		}
		diffm[name] = diffDetection(d, resolveThreshold)
	}

	pass, err := generateReport(o.writer, diffm)
	if err != nil {
		return errors.Wrap(err, "generate report")
	}
	if !pass {
		// Resolved per-(file, family) threshold is rendered per row in the
		// report's Threshold column, so the exit error stays threshold-free to
		// avoid implying the default was the one that tripped.
		return errors.New("diff failed: change rate exceeded the applicable threshold for at least one (scan-result file, source family); see report for details")
	}
	return nil
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
func detectAll(baselineBin, baselineDB, targetBin, targetDB string, files map[string]string) (map[string]FileDiff, error) {
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
		ids  map[string][]string // family → CVE IDs
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
			slog.Debug("vuls0 detect done", "role", t.role, "name", t.name, "families", len(ids))
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, errors.Wrap(err, "vuls0 detection")
	}
	close(resChan)

	diffm := make(map[string]FileDiff, len(files))
	for name := range files {
		diffm[name] = FileDiff{Name: name}
	}
	for r := range resChan {
		d := diffm[r.name]
		switch r.role {
		case "baseline":
			d.BaselineIDs = r.ids
		case "target":
			d.TargetIDs = r.ids
		}
		diffm[r.name] = d
	}

	return diffm, nil
}

// vulnInfo is the minimal projection of a vuls0 models.VulnInfo needed to
// attribute a detected CVE to source families.
type vulnInfo struct {
	Confidences []confidence `json:"confidences"`
}

type confidence struct {
	DetectionMethod string `json:"detectionMethod"`
}

// runVuls0Report runs vuls0 report on a single scan result file and returns
// detected CVE IDs grouped by source family.
func runVuls0Report(ctx context.Context, binary, dbpath, scanResultPath string) (map[string][]string, error) {
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

	return collectFamilies(sr.ScannedCves), nil
}

// collectFamilies groups detected CVE IDs by source family, derived from each
// CVE's confidences. Confidences are appended only by detection paths in
// vuls0 (enrichment adds cveContents but never confidences), so they are a
// clean per-source detection signal. A CVE detected by multiple families is
// counted under each. A CVE without confidences lands in "unknown".
// ID lists are sorted for deterministic diff output.
func collectFamilies(scannedCves map[string]vulnInfo) map[string][]string {
	m := make(map[string][]string)
	for cve, vi := range scannedCves {
		families := make(map[string]struct{})
		for _, c := range vi.Confidences {
			families[detectionMethodFamily(c.DetectionMethod)] = struct{}{}
		}
		if len(families) == 0 {
			families["unknown"] = struct{}{}
		}
		for f := range families {
			m[f] = append(m[f], cve)
		}
	}
	for _, ids := range m {
		slices.Sort(ids)
	}
	return m
}

// detectionMethodFamily maps a vuls0 confidences[].detectionMethod string to
// a source family. The three match-tier suffixes are collapsed so a tier flip
// (e.g. cpematch expansion demoting ExactVersionMatch to VendorProductMatch)
// registers as a content change within one family, not as an add+remove
// across two. Unrecognized methods pass through verbatim (e.g. "OvalMatch",
// "DebianSecurityTrackerMatch", "UbuntuAPIMatch").
func detectionMethodFamily(method string) string {
	for _, suffix := range []string{"ExactVersionMatch", "RoughVersionMatch", "VendorProductMatch"} {
		if prefix, ok := strings.CutSuffix(method, suffix); ok && prefix != "" {
			return prefix // "Nvd", "Vulncheck", "Jvn", "Fortinet", "Paloalto", "Cisco"
		}
	}
	switch method {
	case "WindowsUpdateSearch", "WindowsRoughMatch":
		return "Windows"
	default:
		return method
	}
}

// diffDetection fills in the per-family diff fields of a single FileDiff.
// Override resolution is the caller's responsibility — resolveThreshold is
// applied verbatim per family. Parallels `diffEcosystem` on the db side.
//
// Only (CVE ID, family) pairs are compared; per-CVE content (confidence
// score, affected packages, CVSS, exploit/KEV metadata, etc.) is not diffed.
// Content-only changes are therefore invisible. This is sufficient for
// regression detection (missing or extra CVEs per source family), but not for
// validating data source migrations where IDs stay the same but metadata
// differs.
func diffDetection(d FileDiff, resolveThreshold func(family string) float64) FileDiff {
	families := make(map[string]struct{}, max(len(d.BaselineIDs), len(d.TargetIDs)))
	for f := range d.BaselineIDs {
		families[f] = struct{}{}
	}
	for f := range d.TargetIDs {
		families[f] = struct{}{}
	}

	d.Families = make([]FamilyDiff, 0, len(families))
	for _, family := range slices.Sorted(maps.Keys(families)) {
		fd := FamilyDiff{
			Family:      family,
			BaselineIDs: d.BaselineIDs[family],
			TargetIDs:   d.TargetIDs[family],
		}
		fd.Added = subtract(fd.TargetIDs, fd.BaselineIDs)
		fd.Removed = subtract(fd.BaselineIDs, fd.TargetIDs)

		// changeRate can exceed 100% when additions outnumber baseline entries.
		// This is intentional — capping at 100 would hide the magnitude of large additions.
		fd.ChangeRate = func() float64 {
			switch {
			case len(fd.BaselineIDs) > 0:
				return float64(len(fd.Added)+len(fd.Removed)) / float64(len(fd.BaselineIDs)) * 100
			case len(fd.Added)+len(fd.Removed) > 0:
				return 100
			default:
				return 0
			}
		}()
		fd.Threshold = resolveThreshold(family)
		fd.Pass = fd.ChangeRate <= fd.Threshold
		d.Families = append(d.Families, fd)
	}
	d.Pass = !slices.ContainsFunc(d.Families, func(fd FamilyDiff) bool { return !fd.Pass })
	return d
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
