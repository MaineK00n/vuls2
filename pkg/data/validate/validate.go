package validate

import (
	"cmp"
	"encoding/json/v2"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
)

// Check is one semantic rule evaluated against a single data.Data.
type Check struct {
	Name        string
	Description string
	Detect      func(data dataTypes.Data) []string
}

// Checks returns the registered check table.
func Checks() []Check {
	return []Check{cpePVPCheck, emptyCriteriaCheck, orphanSegmentCheck}
}

// Finding is one semantic violation found in an extracted data file.
type Finding struct {
	Path    string           `json:"path"`
	ID      dataTypes.RootID `json:"id,omitempty"`
	Check   string           `json:"check"`
	Message string           `json:"message"`
}

type options struct {
	checks      []string
	concurrency int
}

type Option interface {
	apply(*options)
}

type checksOption []string

func (o checksOption) apply(opts *options) {
	opts.checks = []string(o)
}

// WithChecks selects checks by name. An empty list means all checks.
func WithChecks(checks []string) Option {
	return checksOption(checks)
}

type concurrencyOption int

func (o concurrencyOption) apply(opts *options) {
	opts.concurrency = int(o)
}

// WithConcurrency sets how many files are validated in parallel.
func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

// Validate walks the extracted data repository under root and runs the
// selected semantic checks against every data/**/*.json file. Findings are
// returned sorted by (Path, Check, Message).
func Validate(root string, opts ...Option) ([]Finding, error) {
	options := &options{
		concurrency: runtime.NumCPU(),
	}
	for _, o := range opts {
		o.apply(options)
	}

	checks, err := resolveChecks(options.checks)
	if err != nil {
		return nil, errors.Wrap(err, "resolve checks")
	}

	if _, err := os.Stat(root); err != nil {
		return nil, errors.Wrapf(err, "stat %s", root)
	}

	dir := filepath.Join(root, "data")
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			slog.Warn("no data directory. nothing to validate", "dir", dir)
			return nil, nil
		}
		return nil, errors.Wrapf(err, "stat %s", dir)
	}

	var paths []string
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".json" {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", dir)
	}

	var (
		findings []Finding
		mu       sync.Mutex
	)
	g := errgroup.Group{}
	g.SetLimit(max(options.concurrency, 1))
	for _, path := range paths {
		g.Go(func() error {
			fs, err := validateFile(root, path, checks)
			if err != nil {
				return errors.Wrapf(err, "validate %s", path)
			}
			if len(fs) > 0 {
				mu.Lock()
				findings = append(findings, fs...)
				mu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	slices.SortFunc(findings, func(x, y Finding) int {
		return cmp.Or(
			cmp.Compare(x.Path, y.Path),
			cmp.Compare(x.Check, y.Check),
			cmp.Compare(x.Message, y.Message),
		)
	})

	return findings, nil
}

func resolveChecks(names []string) ([]Check, error) {
	if len(names) == 0 {
		return Checks(), nil
	}

	var checks []Check
	for _, name := range names {
		i := slices.IndexFunc(Checks(), func(c Check) bool { return c.Name == name })
		if i < 0 {
			return nil, errors.Errorf("unknown check %q. accepts: %q", name, slices.Collect(func(yield func(string) bool) {
				for _, c := range Checks() {
					if !yield(c.Name) {
						return
					}
				}
			}))
		}
		checks = append(checks, Checks()[i])
	}
	return checks, nil
}

func validateFile(root, path string, checks []Check) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	var data dataTypes.Data
	if err := json.UnmarshalRead(f, &data); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %s", path)
	}

	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}

	var findings []Finding
	for _, c := range checks {
		for _, m := range c.Detect(data) {
			findings = append(findings, Finding{
				Path:    filepath.ToSlash(rel),
				ID:      data.ID,
				Check:   c.Name,
				Message: m,
			})
		}
	}
	return findings, nil
}

// walkCriteria visits every criterion in the criteria tree rooted at ca.
func walkCriteria(ca criteriaTypes.Criteria, fn func(cn criterionTypes.Criterion)) {
	for _, child := range ca.Criterias {
		walkCriteria(child, fn)
	}
	for _, cn := range ca.Criterions {
		fn(cn)
	}
}
