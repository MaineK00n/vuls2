package data

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
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
	Detect      func(data dataTypes.Data) []Detected
}

// Detected is one violation reported by a Check. Pointer addresses the
// offending element within the file as an RFC 6901 JSON pointer (e.g.
// /advisories/0/segments/2); Validate resolves it to Finding.Line, and the
// pointer itself is not carried on Finding.
type Detected struct {
	Pointer string
	Message string
}

// Checks returns the registered check table.
func Checks() []Check {
	return []Check{cpePVPCheck, emptyCriteriaCheck, orphanSegmentCheck}
}

// Finding is one semantic violation found in an extracted data file. Line
// is the 1-based line number of the offending element (0 when it could not
// be resolved).
type Finding struct {
	Path    string           `json:"path"`
	Line    int              `json:"line,omitempty"`
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
// returned sorted by (Path, Check, Message, Line).
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

	info, err := os.Stat(root)
	if err != nil {
		return nil, errors.Wrapf(err, "stat %s", root)
	}
	if !info.IsDir() {
		return nil, errors.Errorf("%s is not a directory", root)
	}

	dir := filepath.Join(root, "data")
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		return nil, errors.Errorf("%s is not a directory", dir)
	} else if err != nil {
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
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(max(options.concurrency, 1))
	for _, path := range paths {
		if ctx.Err() != nil {
			break
		}
		g.Go(func() error {
			fileFindings, err := validateFile(root, path, checks)
			if err != nil {
				return errors.Wrapf(err, "validate %s", path)
			}
			if len(fileFindings) > 0 {
				mu.Lock()
				findings = append(findings, fileFindings...)
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
			cmp.Compare(x.Line, y.Line),
		)
	})

	return findings, nil
}

func resolveChecks(names []string) ([]Check, error) {
	all := Checks()
	if len(names) == 0 {
		return all, nil
	}

	checks := make([]Check, 0, len(names))
	for _, name := range names {
		i := slices.IndexFunc(all, func(c Check) bool { return c.Name == name })
		if i < 0 {
			accepted := make([]string, 0, len(all))
			for _, c := range all {
				accepted = append(accepted, c.Name)
			}
			return nil, errors.Errorf("unknown check %q. accepts: %q", name, accepted)
		}
		if !slices.ContainsFunc(checks, func(c Check) bool { return c.Name == name }) {
			checks = append(checks, all[i])
		}
	}
	return checks, nil
}

func validateFile(root, path string, checks []Check) ([]Finding, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "read %s", path)
	}

	var data dataTypes.Data
	if err := json.Unmarshal(bs, &data); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %s", path)
	}

	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}

	var (
		findings []Finding
		pointers []string
	)
	for _, c := range checks {
		for _, d := range c.Detect(data) {
			findings = append(findings, Finding{
				Path:    filepath.ToSlash(rel),
				ID:      data.ID,
				Check:   c.Name,
				Message: d.Message,
			})
			pointers = append(pointers, d.Pointer)
		}
	}
	if len(findings) == 0 {
		return nil, nil
	}

	lines := resolveLines(bs, pointers)
	for i := range findings {
		findings[i].Line = lines[pointers[i]]
	}
	return findings, nil
}

// resolveLines maps each JSON pointer in pointers to the 1-based line number
// of its value in bs. Only files that produced findings pay for this second
// tokenizing pass. Pointers that cannot be located map to 0.
func resolveLines(bs []byte, pointers []string) map[string]int {
	wanted := make(map[string]struct{}, len(pointers))
	for _, p := range pointers {
		if p != "" {
			wanted[p] = struct{}{}
		}
	}

	lines := make(map[string]int, len(wanted))
	dec := jsontext.NewDecoder(bytes.NewReader(bs))
	// The decoder advances monotonically, so the line counter is carried
	// incrementally between matches; every byte is scanned exactly once
	// regardless of how many pointers resolve.
	line, counted := 1, int64(0)
	for len(lines) < len(wanted) {
		if _, err := dec.ReadToken(); err != nil {
			// io.EOF, or a malformed tail that Unmarshal tolerated; report
			// what has been resolved so far.
			break
		}
		ptr := string(dec.StackPointer())
		if _, ok := wanted[ptr]; !ok {
			continue
		}
		if _, done := lines[ptr]; done {
			continue
		}
		offset := min(dec.InputOffset(), int64(len(bs)))
		line += bytes.Count(bs[counted:offset], []byte("\n"))
		counted = offset
		lines[ptr] = line
	}
	return lines
}

// walkCriteria visits every criterion in the criteria tree rooted at ca,
// passing the JSON pointer of each criterion relative to the tree root ptr.
func walkCriteria(ptr string, ca criteriaTypes.Criteria, fn func(ptr string, cn criterionTypes.Criterion)) {
	for i, child := range ca.Criterias {
		walkCriteria(fmt.Sprintf("%s/criterias/%d", ptr, i), child, fn)
	}
	for i, cn := range ca.Criterions {
		fn(fmt.Sprintf("%s/criterions/%d", ptr, i), cn)
	}
}
