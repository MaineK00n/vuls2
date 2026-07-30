package validate

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
)

// DataRule is one semantic rule evaluated against a single data.Data.
type DataRule struct {
	Name        string
	Description string
	Inspect     func(data dataTypes.Data) []Violation
}

// Violation is a single rule violation reported by a DataRule. Pointer
// addresses the offending element within the file as an RFC 6901 JSON
// pointer (e.g. /advisories/0/segments/2); Validate resolves it to
// Finding.Line, and the pointer itself is not carried on Finding.
type Violation struct {
	Pointer string
	Message string
}

// DataRules returns the registered per-file rule table for the data content
// directory. Rules that inspect the detection criteria trees live in the
// CriteriaRules table instead and share a single walk.
func DataRules() []DataRule {
	return []DataRule{orphanSegmentRule}
}

// RepositoryRule is one rule evaluated against the repository as a whole
// (its top-level layout) rather than a single data file. Inspect fills
// Finding.Path/Message itself; Rule and Line handling stay with the
// framework conventions (repository findings carry no line).
type RepositoryRule struct {
	Name        string
	Description string
	Inspect     func(root string) ([]Finding, error)
}

// RepositoryRules returns the registered repository-level rule table.
func RepositoryRules() []RepositoryRule {
	return []RepositoryRule{layoutRule}
}

// Finding is one semantic violation found in an extracted data file. Line
// is the 1-based line number of the offending element (0 when it could not
// be resolved).
type Finding struct {
	RootID  dataTypes.RootID `json:"root_id,omitempty"`
	Path    string           `json:"path"`
	Line    int              `json:"line,omitzero"`
	Rule    string           `json:"rule"`
	Message string           `json:"message"`
}

// Compare is the canonical total order over findings: by RootID, then
// Path, Line, Rule, Message — line order within a file, like compiler
// diagnostics, rather than grouped by rule. Validate returns findings
// unordered; output layers sort with this.
func (f Finding) Compare(other Finding) int {
	return cmp.Or(
		cmp.Compare(f.RootID, other.RootID),
		cmp.Compare(f.Path, other.Path),
		cmp.Compare(f.Line, other.Line),
		cmp.Compare(f.Rule, other.Rule),
		cmp.Compare(f.Message, other.Message),
	)
}

type options struct {
	rules       []string
	concurrency int
}

type Option interface {
	apply(*options)
}

type rulesOption []string

func (o rulesOption) apply(opts *options) {
	opts.rules = []string(o)
}

// WithRules selects rules by name. An empty list means all rules.
func WithRules(rules []string) Option {
	return rulesOption(rules)
}

type concurrencyOption int

func (o concurrencyOption) apply(opts *options) {
	opts.concurrency = int(o)
}

// WithConcurrency sets how many files are validated in parallel.
func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

// Validate runs the selected rules against the extracted repository under
// root: repository-level rules against its top-level layout, and per-file
// semantic rules against every data/**/*.json file when the data content
// directory is present. Content directories are auto-detected — callers
// never say which kinds the repository carries. Findings are returned in
// no guaranteed order; callers needing one sort with Finding.Compare.
func Validate(root string, opts ...Option) ([]Finding, error) {
	options := &options{
		concurrency: runtime.NumCPU(),
	}
	for _, o := range opts {
		o.apply(options)
	}

	dataRules, criteriaRules, repoRules, err := resolveRules(options.rules)
	if err != nil {
		return nil, errors.Wrap(err, "resolve rules")
	}

	info, err := os.Stat(root)
	if err != nil {
		return nil, errors.Wrapf(err, "stat %s", root)
	}
	if !info.IsDir() {
		return nil, errors.Errorf("%s is not a directory", root)
	}

	// datasource.json is what identifies the target as an extracted
	// repository in the first place; without it there is nothing to
	// validate, so like a missing root this is an error, not a finding.
	switch info, err := os.Stat(filepath.Join(root, "datasource.json")); {
	case err == nil && info.Mode().IsRegular():
	case err == nil:
		return nil, errors.Errorf("%s is not a regular file", filepath.Join(root, "datasource.json"))
	case errors.Is(err, fs.ErrNotExist):
		return nil, errors.Errorf("%s is missing", filepath.Join(root, "datasource.json"))
	default:
		return nil, errors.Wrapf(err, "stat %s", filepath.Join(root, "datasource.json"))
	}

	var findings []Finding
	for _, c := range repoRules {
		repoFindings, err := c.Inspect(root)
		if err != nil {
			return nil, errors.Wrapf(err, "inspect %s", c.Name)
		}
		findings = append(findings, repoFindings...)
	}

	// Layout problems (a content name that is not a directory, unknown
	// entries, ...) are reported above; the per-file walk only covers the
	// content kinds that have file-level rules selected and are actually
	// present — with no per-file rules there is nothing to read.
	var paths []string
	if len(dataRules)+len(criteriaRules) > 0 {
		dir := filepath.Join(root, "data")
		switch info, err := os.Stat(dir); {
		case err == nil && info.IsDir():
			if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return errors.Wrapf(err, "walk %s", path)
				}
				if !d.IsDir() && filepath.Ext(path) == ".json" {
					paths = append(paths, path)
				}
				return nil
			}); err != nil {
				return nil, errors.Wrapf(err, "walk %s", dir)
			}
		case err == nil:
			// Present but not a directory: the repository is statically
			// broken for per-file rules, so fail instead of silently
			// producing a result that never read any file.
			return nil, errors.Errorf("%s is not a directory", dir)
		case !errors.Is(err, fs.ErrNotExist):
			// A stat error other than absence (permission, IO) must not
			// yield a false clean result; db add treats it as fatal too.
			return nil, errors.Wrapf(err, "stat %s", dir)
		default:
			// Absent is a legitimate layout — repositories without data
			// content exist; whether that is a problem is the layout
			// rule's finding, not a walk error.
		}
	}

	// Each worker owns its own results slot, so no lock is needed; the
	// happens-before edge of g.Wait makes the writes visible here.
	results := make([][]Finding, len(paths))
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(max(options.concurrency, 1))
	for i, path := range paths {
		if ctx.Err() != nil {
			break
		}
		g.Go(func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			fileFindings, err := validateFile(root, path, dataRules, criteriaRules)
			if err != nil {
				return errors.Wrapf(err, "validate %s", path)
			}
			results[i] = fileFindings
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	for _, fileFindings := range results {
		findings = append(findings, fileFindings...)
	}

	return findings, nil
}

func resolveRules(names []string) ([]DataRule, []CriteriaRule, []RepositoryRule, error) {
	allData, allCriteria, allRepo := DataRules(), CriteriaRules(), RepositoryRules()
	if len(names) == 0 {
		return allData, allCriteria, allRepo, nil
	}

	dataRules := make([]DataRule, 0, len(names))
	criteriaRules := make([]CriteriaRule, 0, len(names))
	repoRules := make([]RepositoryRule, 0, len(names))
	for _, name := range names {
		switch {
		case slices.ContainsFunc(allData, func(c DataRule) bool { return c.Name == name }):
			i := slices.IndexFunc(allData, func(c DataRule) bool { return c.Name == name })
			if !slices.ContainsFunc(dataRules, func(c DataRule) bool { return c.Name == name }) {
				dataRules = append(dataRules, allData[i])
			}
		case slices.ContainsFunc(allCriteria, func(c CriteriaRule) bool { return c.Name == name }):
			i := slices.IndexFunc(allCriteria, func(c CriteriaRule) bool { return c.Name == name })
			if !slices.ContainsFunc(criteriaRules, func(c CriteriaRule) bool { return c.Name == name }) {
				criteriaRules = append(criteriaRules, allCriteria[i])
			}
		case slices.ContainsFunc(allRepo, func(c RepositoryRule) bool { return c.Name == name }):
			i := slices.IndexFunc(allRepo, func(c RepositoryRule) bool { return c.Name == name })
			if !slices.ContainsFunc(repoRules, func(c RepositoryRule) bool { return c.Name == name }) {
				repoRules = append(repoRules, allRepo[i])
			}
		default:
			acceptable := make([]string, 0, len(allData)+len(allCriteria)+len(allRepo))
			for _, c := range allData {
				acceptable = append(acceptable, c.Name)
			}
			for _, c := range allCriteria {
				acceptable = append(acceptable, c.Name)
			}
			for _, c := range allRepo {
				acceptable = append(acceptable, c.Name)
			}
			return nil, nil, nil, errors.Errorf("unknown rule %q. accepts: %q", name, acceptable)
		}
	}
	return dataRules, criteriaRules, repoRules, nil
}

func validateFile(root, path string, dataRules []DataRule, criteriaRules []CriteriaRule) ([]Finding, error) {
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
		return nil, errors.Wrapf(err, "rel %s %s", root, path)
	}

	var vs []attributed
	for _, c := range dataRules {
		for _, v := range c.Inspect(data) {
			vs = append(vs, attributed{rule: c.Name, Violation: v})
		}
	}
	vs = append(vs, inspectCriteria(data, criteriaRules)...)

	var (
		findings []Finding
		pointers []string
	)
	for _, v := range vs {
		findings = append(findings, Finding{
			RootID:  data.ID,
			Path:    filepath.ToSlash(rel),
			Rule:    v.rule,
			Message: v.Message,
		})
		pointers = append(pointers, v.Pointer)
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
