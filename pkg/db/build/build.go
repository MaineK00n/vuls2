package build

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/pull"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

	dbAdd "github.com/MaineK00n/vuls2/pkg/db/add"
	dbInit "github.com/MaineK00n/vuls2/pkg/db/init"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
	"github.com/MaineK00n/vuls2/pkg/version"
)

type options struct {
	dbtype      string
	dbpath      string
	storageopts session.StorageOptions

	dir      string
	parallel int
	report   string

	debug bool
}

type Option interface {
	apply(*options)
}

type dbtypeOption string

func (o dbtypeOption) apply(opts *options) {
	opts.dbtype = string(o)
}

func WithDBType(dbtype string) Option {
	return dbtypeOption(dbtype)
}

type dbpathOption string

func (o dbpathOption) apply(opts *options) {
	opts.dbpath = string(o)
}

func WithDBPath(dbpath string) Option {
	return dbpathOption(dbpath)
}

type storageoptsOption session.StorageOptions

func (o storageoptsOption) apply(opts *options) {
	opts.storageopts = session.StorageOptions(o)
}

func WithStorageOptions(storageopts session.StorageOptions) Option {
	return storageoptsOption(storageopts)
}

type dirOption string

func (o dirOption) apply(opts *options) {
	opts.dir = string(o)
}

// WithDir sets the directory the dotgits are pulled into. Each tree is
// removed as soon as it has been added. Empty means a temporary directory
// that is removed when the build ends.
func WithDir(dir string) Option {
	return dirOption(dir)
}

type parallelOption int

func (o parallelOption) apply(opts *options) {
	opts.parallel = int(o)
}

// WithParallel sets how many dotgits are pulled at once. It is also the
// upper bound on how many extracted trees sit on disk at the same time, since
// a tree is only released after it has been added.
func WithParallel(parallel int) Option {
	return parallelOption(parallel)
}

type reportOption string

func (o reportOption) apply(opts *options) {
	opts.report = string(o)
}

// WithReport writes the Report as JSON to path once the build has succeeded.
func WithReport(path string) Option {
	return reportOption(path)
}

type debugOption bool

func (o debugOption) apply(opts *options) {
	opts.debug = bool(o)
}

func WithDebug(debug bool) Option {
	return debugOption(debug)
}

// Report describes what a build put in the db and how far each source's lock
// commit sits behind its branch.
type Report struct {
	VulsVersion string         `json:"vuls_version"`
	Branch      string         `json:"branch"`
	Registry    string         `json:"registry"`
	Sources     []SourceReport `json:"sources"`
}

// SourceReport is the Report entry of one source.
type SourceReport struct {
	Name       string               `json:"name"`
	ID         sourceTypes.SourceID `json:"id"`
	Repository string               `json:"repository"`

	Commit     string    `json:"commit"`
	CommitDate time.Time `json:"commit_date"`

	BranchHead     string    `json:"branch_head"`
	BranchHeadDate time.Time `json:"branch_head_date"`

	// Behind is how many commits the branch has after Commit. NextCommit is
	// the first of them: its date is when the source started waiting.
	Behind         int        `json:"behind"`
	NextCommit     string     `json:"next_commit,omitempty"`
	NextCommitDate *time.Time `json:"next_commit_date,omitempty"`
}

// Build initializes a db and adds every source of the lock at its pinned
// commit, in lock order. Dotgits are pulled in parallel; adds are serial.
//
// A boltdb is built in a temporary file next to dbpath and renamed over it
// only when every source has been added and verified, so a failed build
// leaves no half-built db behind and never touches an existing one. Other db
// types are built in place.
func Build(lock Lock, opts ...Option) (*Report, error) {
	options := &options{
		dbtype:      "boltdb",
		dbpath:      filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		storageopts: session.StorageOptions{BoltDB: bolt.DefaultOptions},
		parallel:    runtime.NumCPU(),
		debug:       false,
	}
	for _, o := range opts {
		o.apply(options)
	}
	if options.parallel < 1 {
		options.parallel = 1
	}

	if err := lock.Validate(); err != nil {
		return nil, errors.Wrap(err, "validate lock")
	}

	// Every invocation gets its own work directory, under options.dir when
	// given, and removes it however the build ends, so a failure cannot leave
	// extracted trees behind.
	if options.dir != "" {
		if err := os.MkdirAll(options.dir, 0755); err != nil {
			return nil, errors.Wrapf(err, "mkdir %s", options.dir)
		}
	}
	workdir, err := os.MkdirTemp(options.dir, "vuls-db-build-*")
	if err != nil {
		return nil, errors.Wrap(err, "mkdir temp")
	}
	defer func() {
		if err := os.RemoveAll(workdir); err != nil {
			slog.Warn("Failed to remove work directory", slog.String("dir", workdir), slog.String("err", err.Error()))
		}
	}()

	// The db is built at target; for boltdb that is a scratch file, unique
	// to this invocation so concurrent builds of the same dbpath cannot
	// touch each other's, renamed over dbpath at the end.
	target := options.dbpath
	if options.dbtype == "boltdb" {
		if err := os.MkdirAll(filepath.Dir(options.dbpath), 0755); err != nil {
			return nil, errors.Wrapf(err, "mkdir %s", filepath.Dir(options.dbpath))
		}
		f, err := os.CreateTemp(filepath.Dir(options.dbpath), fmt.Sprintf(".%s.build-*", filepath.Base(options.dbpath)))
		if err != nil {
			return nil, errors.Wrapf(err, "create scratch db in %s", filepath.Dir(options.dbpath))
		}
		target = f.Name()
		if err := f.Close(); err != nil {
			return nil, errors.Wrapf(err, "close %s", target)
		}
		// The scratch db is renamed away on success; on any other exit it
		// must not be left next to dbpath.
		defer func() {
			if err := os.RemoveAll(target); err != nil && !os.IsNotExist(err) {
				slog.Warn("Failed to remove scratch db", slog.String("dbpath", target), slog.String("err", err.Error()))
			}
		}()
	}

	// The report is written after the db has been verified, so a report
	// path that is the db (or its scratch file) would replace a good db with
	// JSON and still report success. Refuse that up front.
	if options.report != "" {
		for _, p := range []string{options.dbpath, target} {
			same, err := samePath(options.report, p)
			if err != nil {
				return nil, err
			}
			if same {
				return nil, errors.Errorf("report path %s is the db path %s", options.report, p)
			}
		}
	}

	slog.Info("Initialize DB", slog.String("dbpath", target))
	if err := dbInit.Init(dbInit.WithDBType(options.dbtype), dbInit.WithDBPath(target), dbInit.WithStorageOptions(options.storageopts), dbInit.WithDebug(options.debug)); err != nil {
		return nil, errors.Wrap(err, "init db")
	}

	report := &Report{
		VulsVersion: version.String(),
		Branch:      lock.Branch,
		Registry:    lock.Registry,
		Sources:     make([]SourceReport, 0, len(lock.Sources)),
	}

	// Pulls run ahead of the adds, at most `parallel` at a time; a slot is
	// held until the tree has been added and removed, which bounds the trees
	// on disk. Adds consume the pulls in lock order, so slots must also be
	// handed out in lock order: one dispatcher admits the sources one by
	// one, which keeps a later source from taking the last slot while the
	// consumer is still waiting on an earlier one that has none.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type prepared struct {
		root string
		rep  SourceReport
		err  error
	}
	slots := make(chan struct{}, options.parallel)
	ready := make([]chan prepared, len(lock.Sources))
	for i := range ready {
		ready[i] = make(chan prepared, 1)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i, s := range lock.Sources {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				for j := i; j < len(lock.Sources); j++ {
					ready[j] <- prepared{err: ctx.Err()}
				}
				return
			}
			wg.Add(1)
			go func(i int, s Source) {
				defer wg.Done()
				root, rep, err := prepare(workdir, lock, s)
				ready[i] <- prepared{root: root, rep: rep, err: err}
			}(i, s)
		}
	}()

	// On error the dispatcher is cancelled and the in-flight pulls are
	// waited for before returning: pull.Pull takes no context, so a pull
	// already running goes on until it finishes or the registry client
	// times out, and the work directory must not be removed under it.
	for i, s := range lock.Sources {
		p := <-ready[i]
		if p.err != nil {
			cancel()
			wg.Wait()
			return nil, errors.Wrapf(p.err, "prepare %s", s.Name)
		}

		slog.Info("Add", slog.String("name", s.Name), slog.String("id", string(p.rep.ID)), slog.String("commit", s.Commit))
		if err := dbAdd.Add(p.root, dbAdd.WithDBType(options.dbtype), dbAdd.WithDBPath(target), dbAdd.WithStorageOptions(options.storageopts), dbAdd.WithDebug(options.debug)); err != nil {
			cancel()
			wg.Wait()
			return nil, errors.Wrapf(err, "add %s", s.Name)
		}
		if err := os.RemoveAll(p.root); err != nil {
			cancel()
			wg.Wait()
			return nil, errors.Wrapf(err, "remove %s", p.root)
		}
		<-slots
		report.Sources = append(report.Sources, p.rep)
	}
	wg.Wait()

	slog.Info("Verify datasources")
	if err := verify(options, target, report); err != nil {
		return nil, errors.Wrap(err, "verify")
	}

	if options.report != "" {
		if err := writeReport(options.report, report); err != nil {
			return nil, errors.Wrapf(err, "write report %s", options.report)
		}
	}

	if target != options.dbpath {
		if err := os.Rename(target, options.dbpath); err != nil {
			return nil, errors.Wrapf(err, "rename %s to %s", target, options.dbpath)
		}
	}
	slog.Info("Built", slog.String("dbpath", options.dbpath), slog.Int("sources", len(report.Sources)))

	return report, nil
}

// prepare pulls one source's dotgit into workdir, checks the commit out and
// stamps datasource.json with it. It returns the tree root ready for add.
func prepare(workdir string, lock Lock, s Source) (string, SourceReport, error) {
	repository := s.Repository(lock.Registry)
	ref, err := remote.NewRepository(repository)
	if err != nil {
		return "", SourceReport{}, errors.Wrapf(err, "parse %s", repository)
	}
	root := filepath.Join(workdir, ref.Reference.Registry, ref.Reference.Repository, ref.Reference.Reference)

	slog.Info("Pull", slog.String("name", s.Name), slog.String("repository", repository))
	// The checkout is done here rather than by pull: the dotgit has no
	// worktree, and checkout --force both detaches at the commit and writes
	// the files in one step.
	if err := pull.Pull(repository, pull.WithDir(workdir), pull.WithCheckout(""), pull.WithRestore(false)); err != nil {
		return "", SourceReport{}, errors.Wrapf(err, "pull %s", repository)
	}

	// The branch must exist as exactly this ref: the lock has already
	// rejected revision syntax, and this keeps a missing branch from being
	// resolved as anything else by the revision-parsing commands below.
	branch := "refs/heads/" + lock.Branch
	if _, err := git(root, "show-ref", "--verify", "--quiet", branch); err != nil {
		return "", SourceReport{}, errors.Errorf("branch %s is not in %s", lock.Branch, repository)
	}
	ok, err := commitExists(root, s.Commit)
	if err != nil {
		return "", SourceReport{}, err
	}
	if !ok {
		return "", SourceReport{}, errors.Errorf("commit %s is not in %s (history truncated or rewritten?)", s.Commit, repository)
	}
	ok, err = isAncestor(root, s.Commit, branch)
	if err != nil {
		return "", SourceReport{}, err
	}
	if !ok {
		return "", SourceReport{}, errors.Errorf("commit %s is not an ancestor of %s in %s", s.Commit, lock.Branch, repository)
	}

	if _, err := git(root, "checkout", "--force", "--detach", s.Commit); err != nil {
		return "", SourceReport{}, err
	}

	rep := SourceReport{Name: s.Name, Repository: repository, Commit: s.Commit}
	if rep.CommitDate, err = authorTime(root, s.Commit); err != nil {
		return "", SourceReport{}, err
	}
	if rep.BranchHead, err = revParse(root, branch); err != nil {
		return "", SourceReport{}, err
	}
	if rep.BranchHeadDate, err = authorTime(root, rep.BranchHead); err != nil {
		return "", SourceReport{}, err
	}
	after, err := commitsAfter(root, s.Commit, branch)
	if err != nil {
		return "", SourceReport{}, err
	}
	rep.Behind = len(after)
	if len(after) > 0 {
		rep.NextCommit = after[0]
		t, err := authorTime(root, after[0])
		if err != nil {
			return "", SourceReport{}, err
		}
		rep.NextCommitDate = &t
	}

	if rep.ID, err = stampDataSource(filepath.Join(root, "datasource.json"), s.Commit, rep.CommitDate); err != nil {
		return "", SourceReport{}, err
	}

	return root, rep, nil
}

// stampDataSource records the checked-out commit and its date as the
// extracted repository of datasource.json, and returns the source ID. This
// is what the previous Makefile-driven build did with jq before vuls db add.
func stampDataSource(path, commit string, date time.Time) (sourceTypes.SourceID, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return "", errors.Wrapf(err, "read %s", path)
	}
	var ds datasourceTypes.DataSource
	if err := json.Unmarshal(bs, &ds); err != nil {
		return "", errors.Wrapf(err, "unmarshal %s", path)
	}
	if ds.ID == "" {
		return "", errors.Errorf("%s: id is empty", path)
	}
	if ds.Extracted == nil {
		ds.Extracted = &repositoryTypes.Repository{}
	}
	ds.Extracted.Commit = commit
	ds.Extracted.Date = &date

	f, err := os.Create(path)
	if err != nil {
		return "", errors.Wrapf(err, "create %s", path)
	}
	defer f.Close()
	if err := json.MarshalWrite(f, ds); err != nil {
		return "", errors.Wrapf(err, "marshal %s", path)
	}
	return ds.ID, nil
}

// verify reads the datasources back from the db and checks them against the
// report one by one: every source is there under the ID its datasource.json
// declared, at the lock commit, and nothing else is.
func verify(options *options, dbpath string, report *Report) error {
	s, err := (&session.Config{
		Type:    options.dbtype,
		Path:    dbpath,
		Debug:   options.debug,
		Options: options.storageopts,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}
	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer s.Storage().Close()

	dss, err := s.Storage().GetDataSources()
	if err != nil {
		return errors.Wrap(err, "get datasources")
	}
	byID := make(map[sourceTypes.SourceID]datasourceTypes.DataSource, len(dss))
	for _, ds := range dss {
		byID[ds.ID] = ds
	}

	seen := make(map[sourceTypes.SourceID]string, len(report.Sources))
	for _, r := range report.Sources {
		if prev, ok := seen[r.ID]; ok {
			return errors.Errorf("%s and %s both have datasource id %q", prev, r.Name, r.ID)
		}
		seen[r.ID] = r.Name

		ds, ok := byID[r.ID]
		if !ok {
			return errors.Errorf("%s: datasource %q is not in the db", r.Name, r.ID)
		}
		if ds.Extracted == nil || ds.Extracted.Commit != r.Commit {
			return errors.Errorf("%s: datasource %q has commit %q, lock has %q", r.Name, r.ID, func() string {
				if ds.Extracted == nil {
					return ""
				}
				return ds.Extracted.Commit
			}(), r.Commit)
		}
	}
	if len(byID) != len(report.Sources) {
		return errors.Errorf("db has %d datasources, lock has %d", len(byID), len(report.Sources))
	}

	return nil
}

// samePath reports whether a and b name the same file: the same path once
// symlinks are resolved (also through parents and dangling links of a file
// that does not exist yet), or (when both exist) the same inode.
func samePath(a, b string) (bool, error) {
	ra, err := resolvePath(a)
	if err != nil {
		return false, err
	}
	rb, err := resolvePath(b)
	if err != nil {
		return false, err
	}
	if ra == rb {
		return true, nil
	}

	fa, err := os.Stat(a)
	if err != nil {
		return false, nil
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false, nil
	}
	return os.SameFile(fa, fb), nil
}

// resolvePath returns the absolute path of p with every symlink resolved,
// including when p itself does not exist yet: the longest existing prefix
// is resolved and the missing tail re-attached, and a dangling symlink is
// followed to where it points.
func resolvePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", errors.Wrapf(err, "abs %s", p)
	}
	return resolveAbs(abs, 0)
}

func resolveAbs(abs string, depth int) (string, error) {
	if depth > 40 {
		return "", errors.Errorf("too many levels of symbolic links: %s", abs)
	}

	real, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return real, nil
	}
	if !os.IsNotExist(err) {
		return "", errors.Wrapf(err, "resolve %s", abs)
	}

	// abs does not exist (or is a dangling symlink). Resolve its parent,
	// then follow the link if there is one.
	parent, base := filepath.Split(abs)
	parent = filepath.Clean(parent)
	if parent == abs {
		return abs, nil
	}
	rp, err := resolveAbs(parent, depth+1)
	if err != nil {
		return "", err
	}
	resolved := filepath.Join(rp, base)

	fi, err := os.Lstat(resolved)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return resolved, nil
	}
	target, err := os.Readlink(resolved)
	if err != nil {
		return "", errors.Wrapf(err, "readlink %s", resolved)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(rp, target)
	}
	return resolveAbs(filepath.Clean(target), depth+1)
}

func writeReport(path string, report *Report) error {
	f, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "create %s", path)
	}
	defer f.Close()
	if err := json.MarshalWrite(f, report, jsontext.WithIndent("  ")); err != nil {
		return errors.Wrap(err, "marshal report")
	}
	return nil
}
