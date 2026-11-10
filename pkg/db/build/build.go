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
	"strings"
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

	dir                 string
	downloadConcurrency int
	restoreConcurrency  int
	report              string

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

type downloadConcurrencyOption int

func (o downloadConcurrencyOption) apply(opts *options) {
	opts.downloadConcurrency = int(o)
}

// WithDownloadConcurrency sets how many dotgits are pulled at once. A pulled
// dotgit is the .git directory only, so this scales network use, not the
// extracted trees on disk.
func WithDownloadConcurrency(n int) Option {
	return downloadConcurrencyOption(n)
}

type restoreConcurrencyOption int

func (o restoreConcurrencyOption) apply(opts *options) {
	opts.restoreConcurrency = int(o)
}

// WithRestoreConcurrency sets how many sources are restored (their tree
// checked out) ahead of the add. Each restored tree stays on disk until it
// has been added, so n+1 trees exist at most: n ahead plus the one being
// added.
func WithRestoreConcurrency(n int) Option {
	return restoreConcurrencyOption(n)
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

	// How long each stage took for this source, in seconds: pulling the
	// dotgit, restoring the tree, and adding it to the db.
	PullSeconds    float64 `json:"pull_seconds"`
	RestoreSeconds float64 `json:"restore_seconds"`
	AddSeconds     float64 `json:"add_seconds"`
}

// Build initializes a db and adds every source of the lock at its pinned
// commit, in lock order. Dotgits are pulled concurrently and trees restored
// ahead of the add; adds are serial.
//
// A boltdb is built in a temporary file next to dbpath and renamed over it
// only when every source has been added and verified, so a failed build
// leaves no half-built db behind and never touches an existing one. Other db
// types are built in place.
func Build(lock Lock, opts ...Option) (*Report, error) {
	options := &options{
		dbtype:              "boltdb",
		dbpath:              filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		storageopts:         session.StorageOptions{BoltDB: bolt.DefaultOptions},
		downloadConcurrency: runtime.NumCPU(),
		restoreConcurrency:  1,
		debug:               false,
	}
	for _, o := range opts {
		o.apply(options)
	}
	options.downloadConcurrency = max(options.downloadConcurrency, 1)
	options.restoreConcurrency = max(options.restoreConcurrency, 1)

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
	created, err := os.MkdirTemp(options.dir, "vuls-db-build-*")
	if err != nil {
		return nil, errors.Wrap(err, "mkdir temp")
	}
	// The kernel resolves "alias/../work" through the symlink, while
	// filepath.Join cleans it lexically to "work". Resolve the created
	// directory once so that downloads, restores and the cleanup below all
	// use the directory that was actually created.
	workdir, err := filepath.EvalSymlinks(created)
	if err != nil {
		if rerr := os.RemoveAll(created); rerr != nil {
			slog.Warn("Failed to remove work directory", slog.String("dir", created), slog.String("err", rerr.Error()))
		}
		return nil, errors.Wrapf(err, "resolve %s", created)
	}
	defer func() {
		if err := os.RemoveAll(workdir); err != nil {
			slog.Warn("Failed to remove work directory", slog.String("dir", workdir), slog.String("err", err.Error()))
		}
	}()

	// The db is built at target; for boltdb that is a scratch file, unique
	// to this invocation so concurrent builds of the same dbpath cannot
	// touch each other's, renamed over dbpath at the end.
	dbpath, target := options.dbpath, options.dbpath
	if options.dbtype == "boltdb" {
		// The scratch db must sit in the directory dbpath is renamed into,
		// or the final rename can cross filesystems. filepath.Dir would clean
		// "alias/../vuls.db" lexically to ".", so split without cleaning and
		// resolve the parent as the kernel does.
		dir, base := filepath.Split(options.dbpath)
		if dir == "" {
			dir = "."
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, errors.Wrapf(err, "mkdir %s", dir)
		}
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return nil, errors.Wrapf(err, "resolve %s", dir)
		}
		dbpath = filepath.Join(resolved, base)

		f, err := os.CreateTemp(resolved, fmt.Sprintf(".%s.build-*", base))
		if err != nil {
			return nil, errors.Wrapf(err, "create scratch db in %s", resolved)
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
		for _, p := range []string{dbpath, target} {
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

	// Three stages. Downloads (the dotgit, i.e. the .git directory only)
	// run ahead for every source, downloadConcurrency at a time, in lock
	// order; they are small (about 1 GiB at most) so all of them may sit on
	// disk. Restores write the extracted tree, which is large, so only
	// restoreConcurrency sources are restored ahead of the one being added:
	// restoreConcurrency+1 trees exist at most. Adds are serial, in lock
	// order, because bbolt has a single writer.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type staged struct {
		root string
		rep  SourceReport
		err  error
	}
	downloaded := make([]chan staged, len(lock.Sources))
	restored := make([]chan staged, len(lock.Sources))
	for i := range lock.Sources {
		downloaded[i] = make(chan staged, 1)
		restored[i] = make(chan staged, 1)
	}
	var wg sync.WaitGroup

	// Stage 1: downloads. One dispatcher admits the sources in lock order
	// so an early source is never starved of a slot by later ones.
	slots := make(chan struct{}, options.downloadConcurrency)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i, s := range lock.Sources {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				for j := i; j < len(lock.Sources); j++ {
					downloaded[j] <- staged{err: ctx.Err()}
				}
				return
			}
			wg.Add(1)
			go func(i int, s Source) {
				defer wg.Done()
				defer func() { <-slots }()
				root, rep, err := download(workdir, lock, s)
				if err != nil {
					cancel()
				}
				downloaded[i] <- staged{root: root, rep: rep, err: err}
			}(i, s)
		}
	}()

	// Stage 2: restores, restoreConcurrency sources ahead of the add. A
	// tree slot is held from restore until the add has removed the tree, and
	// is handed out in lock order like the download slots.
	trees := make(chan struct{}, options.restoreConcurrency+1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i, s := range lock.Sources {
			select {
			case trees <- struct{}{}:
			case <-ctx.Done():
				for j := i; j < len(lock.Sources); j++ {
					restored[j] <- staged{err: ctx.Err()}
				}
				return
			}
			wg.Add(1)
			go func(i int, s Source) {
				defer wg.Done()
				var d staged
				select {
				case d = <-downloaded[i]:
				case <-ctx.Done():
					d = staged{err: ctx.Err()}
				}
				if d.err == nil {
					d.rep, d.err = restore(d.root, s, d.rep)
					if d.err != nil {
						cancel()
					}
				}
				restored[i] <- d
			}(i, s)
		}
	}()

	// Stage 3: adds. On error the other stages are cancelled and waited
	// for before returning: pull.Pull takes no context, so a download already
	// running goes on until it finishes or the registry client times out,
	// and the work directory must not be removed under it.
	fail := func(err error) (*Report, error) {
		cancel()
		wg.Wait()
		return nil, err
	}
	for i, s := range lock.Sources {
		c := <-restored[i]
		if c.err != nil {
			if errors.Is(c.err, context.Canceled) {
				// The real error is in the stage that cancelled; find it.
				wg.Wait()
				for j := range lock.Sources {
					select {
					case d := <-downloaded[j]:
						if d.err != nil && !errors.Is(d.err, context.Canceled) {
							return fail(errors.Wrapf(d.err, "download %s", lock.Sources[j].Name))
						}
					default:
					}
					select {
					case d := <-restored[j]:
						if d.err != nil && !errors.Is(d.err, context.Canceled) {
							return fail(errors.Wrapf(d.err, "restore %s", lock.Sources[j].Name))
						}
					default:
					}
				}
			}
			return fail(errors.Wrapf(c.err, "prepare %s", s.Name))
		}

		slog.Info("Add", slog.String("name", s.Name), slog.String("id", string(c.rep.ID)), slog.String("commit", s.Commit))
		addStart := time.Now()
		if err := dbAdd.Add(c.root, dbAdd.WithDBType(options.dbtype), dbAdd.WithDBPath(target), dbAdd.WithStorageOptions(options.storageopts), dbAdd.WithDebug(options.debug)); err != nil {
			return fail(errors.Wrapf(err, "add %s", s.Name))
		}
		c.rep.AddSeconds = time.Since(addStart).Seconds()
		slog.Info("Added", slog.String("name", s.Name), slog.Duration("elapsed", time.Since(addStart).Round(time.Millisecond)))
		if err := os.RemoveAll(c.root); err != nil {
			return fail(errors.Wrapf(err, "remove %s", c.root))
		}
		<-trees
		report.Sources = append(report.Sources, c.rep)
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

	if target != dbpath {
		if err := os.Rename(target, dbpath); err != nil {
			return nil, errors.Wrapf(err, "rename %s to %s", target, dbpath)
		}
	}
	slog.Info("Built", slog.String("dbpath", dbpath), slog.Int("sources", len(report.Sources)))

	return report, nil
}

// download pulls one source's dotgit (its .git only, no worktree) into
// workdir, checks that the lock commit belongs to the branch, and reads the
// commit facts the report needs. It returns the repository root.
func download(workdir string, lock Lock, s Source) (string, SourceReport, error) {
	repository := s.Repository(lock.Registry)
	ref, err := remote.NewRepository(repository)
	if err != nil {
		return "", SourceReport{}, errors.Wrapf(err, "parse %s", repository)
	}
	root := filepath.Join(workdir, ref.Reference.Registry, ref.Reference.Repository, ref.Reference.Reference)

	slog.Info("Pull", slog.String("name", s.Name), slog.String("repository", repository))
	start := time.Now()
	if err := pull.Pull(repository, pull.WithDir(workdir), pull.WithCheckout(""), pull.WithRestore(false)); err != nil {
		return "", SourceReport{}, errors.Wrapf(err, "pull %s", repository)
	}
	rep := SourceReport{Name: s.Name, Repository: repository, Commit: s.Commit, PullSeconds: time.Since(start).Seconds()}
	slog.Info("Pulled", slog.String("name", s.Name), slog.Duration("elapsed", time.Since(start).Round(time.Millisecond)))

	// The branch must exist as exactly this ref: the lock has already
	// rejected revision syntax, and this keeps a missing branch from being
	// resolved as anything else by the revision-parsing commands below.
	branch := fmt.Sprintf("refs/heads/%s", lock.Branch)
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

	return root, rep, nil
}

// restore writes the tree of the lock commit into the downloaded repository
// and stamps datasource.json with the commit. The dotgit has no worktree,
// and checkout --force both detaches at the commit and writes the files in
// one step.
func restore(root string, s Source, rep SourceReport) (SourceReport, error) {
	start := time.Now()
	if _, err := git(root, "checkout", "--force", "--detach", s.Commit); err != nil {
		return SourceReport{}, err
	}
	id, err := stampDataSource(filepath.Join(root, "datasource.json"), s.Commit, rep.CommitDate)
	if err != nil {
		return SourceReport{}, err
	}
	rep.ID = id
	rep.RestoreSeconds = time.Since(start).Seconds()
	slog.Info("Restored", slog.String("name", s.Name), slog.String("id", string(id)), slog.Duration("elapsed", time.Since(start).Round(time.Millisecond)))
	return rep, nil
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

// resolvePath returns p as an absolute path with every symlink resolved,
// including when p itself does not exist yet. The path is walked in
// filesystem order: a symlink is followed where it is met and ".." applies
// to the directory reached so far, so "alias/../x" with alias -> real/sub
// resolves to real/x as the kernel would, not to the lexical parent of
// alias. Once a component is missing, the rest is kept as written.
func resolvePath(p string) (string, error) {
	if !filepath.IsAbs(p) {
		wd, err := os.Getwd()
		if err != nil {
			return "", errors.Wrap(err, "getwd")
		}
		p = fmt.Sprintf("%s%c%s", wd, filepath.Separator, p)
	}
	return walkPath(p, 0)
}

func walkPath(p string, depth int) (string, error) {
	if depth > 40 {
		return "", errors.Errorf("too many levels of symbolic links: %s", p)
	}

	// Start at the root of p's volume (empty on Unix; a drive or UNC share
	// on Windows, which must not be split into components) and walk the
	// rest with separators normalized.
	vol := filepath.VolumeName(p)
	cur := fmt.Sprintf("%s%c", vol, filepath.Separator)
	comps := strings.Split(filepath.ToSlash(p[len(vol):]), "/")
	missing := false
	for i, c := range comps {
		switch c {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, c)
		if missing {
			cur = next
			continue
		}
		fi, err := os.Lstat(next)
		if err != nil {
			if !os.IsNotExist(err) {
				return "", errors.Wrapf(err, "lstat %s", next)
			}
			missing = true
			cur = next
			continue
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", errors.Wrapf(err, "readlink %s", next)
		}
		if !filepath.IsAbs(target) {
			target = fmt.Sprintf("%s%c%s", cur, filepath.Separator, target)
		}
		// Continue from the link target with the remaining components, so a
		// ".." that follows the link applies to where the link points.
		return walkPath(filepath.FromSlash(fmt.Sprintf("%s/%s", target, strings.Join(comps[i+1:], "/"))), depth+1)
	}
	return cur, nil
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
