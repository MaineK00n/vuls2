package build

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/contains"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/pull"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/show"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

	dbAdd "github.com/MaineK00n/vuls2/pkg/db/add"
	dbInit "github.com/MaineK00n/vuls2/pkg/db/init"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

type options struct {
	dbtype      string
	dbpath      string
	storageopts session.StorageOptions

	dir string

	writeLock string

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

// WithDir sets the directory under which the build creates its own work
// directory: the dotgits are pulled into it, each tree is removed as soon
// as it has been added, and the work directory is removed when Build
// returns. It defaults to the vuls cache directory, where the db goes by
// default, rather than the system temporary directory, which may be tmpfs
// and would hold the largest trees in memory. Empty means the system
// temporary directory.
func WithDir(dir string) Option {
	return dirOption(dir)
}

type writeLockOption string

func (o writeLockOption) apply(opts *options) {
	opts.writeLock = string(o)
}

// WithWriteLock makes Build write the lock it built to path ("-" writes
// stdout): the same sources, with the commit each one was built at filled in.
// A source that follows its branch thus gets the commit it took, so the db can
// be built again. path may name the lock that was read, to pin every following
// source at the head it took. A symlink at path is followed, an existing file
// keeps its mode, and path's directory is made. Empty writes nothing.
func WithWriteLock(path string) Option {
	return writeLockOption(path)
}

type debugOption bool

func (o debugOption) apply(opts *options) {
	opts.debug = bool(o)
}

func WithDebug(debug bool) Option {
	return debugOption(debug)
}

// Build reads the lock at lockPath ("-" reads stdin), initializes a db and
// adds every source of the lock at its commit, or at the head of its branch
// for a source without one, one source at a time in lock order: pull the
// dotgit with the tree of the commit written out, check that the commit
// belongs to the source's branch, add it and remove it.
// Adding in lock order makes the data in the db the same for the same lock: a
// vulnerability root lists its sources in the order they were added. The file
// itself is not the same byte for byte, as LastModified and the page layout
// vary.
//
// The db is built in a temporary file next to dbpath and renamed to dbpath
// only when every source has been added and verified, so a build that returns
// an error leaves no half-built db behind. A lock to write (WithWriteLock) is
// written to a scratch file next to its path before that rename and renamed
// over its path after it; only a failure of that last rename returns an error
// with the db in place. A process killed by a signal skips that cleanup and
// may leave the work directory and the scratch files behind.
func Build(lockPath string, opts ...Option) error {
	options := &options{
		dbtype:      "boltdb",
		dbpath:      filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		storageopts: session.StorageOptions{BoltDB: bolt.DefaultOptions},
		dir:         utilos.UserCacheDir(),
		debug:       false,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if options.dbtype != "boltdb" {
		return errors.Errorf("unexpected dbtype. accepts: %q, actual: %q", []string{"boltdb"}, options.dbtype)
	}

	lock, err := readLock(lockPath)
	if err != nil {
		return errors.Wrap(err, "read lock")
	}

	// The scratch db is renamed to dbpath at the end, so dbpath must name a
	// file: "out/" would only fail at that rename, after every source.
	switch _, base := filepath.Split(options.dbpath); base {
	case "", ".", "..":
		return errors.Errorf("db %s does not name a file", options.dbpath)
	}
	// The db file must not exist yet, so that nothing is overwritten. Lstat,
	// so that a dangling symlink counts as existing.
	if _, err := os.Lstat(options.dbpath); err == nil {
		return errors.Errorf("db %s already exists", options.dbpath)
	} else if !os.IsNotExist(err) {
		return errors.Wrapf(err, "lstat %s", options.dbpath)
	}
	// Likewise the lock written at the end must name a file.
	if options.writeLock != "" && options.writeLock != "-" {
		switch _, base := filepath.Split(options.writeLock); base {
		case "", ".", "..":
			return errors.Errorf("lock %s does not name a file", options.writeLock)
		}
	}

	// The db is built at target, a scratch file unique to this invocation so
	// concurrent builds of the same dbpath cannot touch each other's, renamed
	// over dbpath at the end. It must sit in the directory dbpath is renamed
	// into, or the final rename can cross filesystems. filepath.Dir would
	// clean "alias/../vuls.db" lexically to "." while the kernel follows
	// alias, so split without cleaning, and resolve the directory once it
	// exists: the scratch db then sits where Rename lands, and the db init,
	// which makes filepath.Dir of its path, finds that directory in place
	// instead of making one next to alias.
	dir, base := filepath.Split(options.dbpath)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.Wrapf(err, "mkdir %s", dir)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return errors.Wrapf(err, "resolve the directory of %s", options.dbpath)
	}

	// The lock is written once every source has been added, so where it goes
	// is settled now, before anything is pulled (prepareLock).
	var out lockOutput
	if options.writeLock != "" && options.writeLock != "-" {
		out, err = prepareLock(options.writeLock, filepath.Join(dir, base))
		if err != nil {
			return errors.Wrapf(err, "write lock %s", options.writeLock)
		}
		defer func() {
			if err := os.Remove(out.scratch); err != nil && !os.IsNotExist(err) {
				slog.Warn("Failed to remove scratch lock", slog.String("path", out.scratch), slog.String("err", err.Error()))
			}
		}()
	}

	// Every invocation gets its own work directory, under options.dir (the
	// system temporary directory when empty), and removes it when Build
	// returns, error or not, so a failure cannot leave extracted trees behind.
	if options.dir != "" {
		if err := os.MkdirAll(options.dir, 0755); err != nil {
			return errors.Wrapf(err, "mkdir %s", options.dir)
		}
	}
	created, err := os.MkdirTemp(options.dir, "vuls-db-build-*")
	if err != nil {
		return errors.Wrap(err, "mkdir temp")
	}
	// The kernel resolves "alias/../work" through the symlink, while
	// filepath.Join cleans it lexically to "work". Resolve the created
	// directory once so that the pulls and the cleanup below all
	// use the directory that was actually created.
	workdir, err := filepath.EvalSymlinks(created)
	if err != nil {
		if rerr := os.RemoveAll(created); rerr != nil {
			slog.Warn("Failed to remove work directory", slog.String("dir", created), slog.String("err", rerr.Error()))
		}
		return errors.Wrapf(err, "resolve %s", created)
	}
	defer func() {
		if err := os.RemoveAll(workdir); err != nil {
			slog.Warn("Failed to remove work directory", slog.String("dir", workdir), slog.String("err", err.Error()))
		}
	}()

	f, err := os.CreateTemp(dir, fmt.Sprintf(".%s.build-*", base))
	if err != nil {
		return errors.Wrapf(err, "create scratch db in %s", dir)
	}
	target := f.Name()
	// The scratch db is renamed away on success; on any other exit, a failed
	// close included, it must not be left next to dbpath.
	defer func() {
		if err := os.RemoveAll(target); err != nil && !os.IsNotExist(err) {
			slog.Warn("Failed to remove scratch db", slog.String("dbpath", target), slog.String("err", err.Error()))
		}
	}()
	if err := f.Close(); err != nil {
		return errors.Wrapf(err, "close %s", target)
	}

	slog.Info("Initialize DB", slog.String("dbpath", target))
	if err := dbInit.Init(dbInit.WithDBType(options.dbtype), dbInit.WithDBPath(target), dbInit.WithStorageOptions(options.storageopts), dbInit.WithDebug(options.debug)); err != nil {
		return errors.Wrap(err, "init db")
	}

	// built is the lock with every source at the commit it was built at,
	// which a source without a commit learns from its pull.
	built := Lock{Sources: slices.Clone(lock.Sources)}
	ids := make([]sourceTypes.SourceID, len(lock.Sources))
	for i, s := range lock.Sources {
		root, id, commit, err := checkout(workdir, s)
		if err != nil {
			return errors.Wrapf(err, "checkout %s", s.Name)
		}
		ids[i] = id
		built.Sources[i].Commit = commit

		slog.Info("Add", slog.String("name", s.Name), slog.String("id", string(ids[i])), slog.String("commit", commit))
		start := time.Now()
		if err := dbAdd.Add(root, dbAdd.WithDBType(options.dbtype), dbAdd.WithDBPath(target), dbAdd.WithStorageOptions(options.storageopts), dbAdd.WithDebug(options.debug)); err != nil {
			return errors.Wrapf(err, "add %s", s.Name)
		}
		slog.Info("Added", slog.String("name", s.Name), slog.Duration("elapsed", time.Since(start).Round(time.Millisecond)))

		// Removed before the next pull: one dotgit and one tree are on disk
		// at a time.
		if err := os.RemoveAll(root); err != nil {
			return errors.Wrapf(err, "remove %s", root)
		}
	}

	slog.Info("Verify datasources")
	if err := verify(options, target, built, ids); err != nil {
		return errors.Wrap(err, "verify")
	}

	// The lock is written out before the db is renamed into place, so a
	// lock that cannot be written stops the build with nothing at dbpath;
	// only its rename comes after the db's.
	if out.scratch != "" {
		if err := out.write(built); err != nil {
			return errors.Wrapf(err, "write lock %s", options.writeLock)
		}
	}

	if err := os.Rename(target, options.dbpath); err != nil {
		return errors.Wrapf(err, "rename %s to %s", target, options.dbpath)
	}
	slog.Info("Built", slog.String("dbpath", options.dbpath), slog.Int("sources", len(lock.Sources)))

	switch options.writeLock {
	case "":
	case "-":
		if err := json.MarshalWrite(os.Stdout, built, jsontext.WithIndent("  ")); err != nil {
			return errors.Wrap(err, "write lock to stdout")
		}
		if _, err := os.Stdout.WriteString("\n"); err != nil {
			return errors.Wrap(err, "write lock to stdout")
		}
	default:
		if err := os.Rename(out.scratch, out.path); err != nil {
			return errors.Wrapf(err, "db %s is in place, but rename %s to %s", options.dbpath, out.scratch, out.path)
		}
		slog.Info("Wrote lock", slog.String("path", out.path))
	}

	return nil
}

// lockOutput is where WithWriteLock's lock goes: a scratch file next to path,
// renamed over path once the db is in place, so path is either left as it was
// or replaced as a whole.
type lockOutput struct {
	path    string
	scratch string
	mode    os.FileMode
}

// prepareLock settles where the lock given as path is written, and fails for
// a place it cannot go to, so that this shows before the build rather than
// after every source. The lock goes to path, or to the file a symlink at path
// points to, so that a lock read through a symlink is updated where it lives.
// Its directory is made, as the db's is. A directory is refused, and so is the
// db path (compared after resolving both, so "./vuls.db", an absolute path or
// a symlinked directory cannot pass for another file). The scratch file is
// created here, so a directory that cannot be written to fails here too. An
// existing file keeps its mode; a new one gets 0644.
func prepareLock(path, dbpath string) (lockOutput, error) {
	out := lockOutput{path: path, mode: 0o644}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			if out.path, err = filepath.EvalSymlinks(path); err != nil {
				return lockOutput{}, errors.Wrapf(err, "resolve %s", path)
			}
			if fi, err = os.Stat(out.path); err != nil {
				return lockOutput{}, errors.Wrapf(err, "stat %s", out.path)
			}
		}
		if fi.IsDir() {
			return lockOutput{}, errors.Errorf("%s is a directory", path)
		}
		out.mode = fi.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return lockOutput{}, errors.Wrapf(err, "lstat %s", path)
	}

	dir, base := filepath.Split(out.path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return lockOutput{}, errors.Wrapf(err, "mkdir %s", dir)
	}
	dir, err := realDir(dir)
	if err != nil {
		return lockOutput{}, errors.Wrapf(err, "resolve the directory of %s", path)
	}
	out.path = filepath.Join(dir, base)
	dbdir, dbbase := filepath.Split(dbpath)
	if dbdir == "" {
		dbdir = "."
	}
	if dbdir, err = realDir(dbdir); err != nil {
		return lockOutput{}, errors.Wrapf(err, "resolve the directory of %s", dbpath)
	}
	if out.path == filepath.Join(dbdir, dbbase) {
		return lockOutput{}, errors.Errorf("%s is the db path", path)
	}

	f, err := os.CreateTemp(dir, fmt.Sprintf(".%s.*", base))
	if err != nil {
		return lockOutput{}, errors.Wrapf(err, "create scratch file in %s", dir)
	}
	if err := f.Close(); err != nil {
		if rerr := os.Remove(f.Name()); rerr != nil {
			slog.Warn("Failed to remove scratch lock", slog.String("path", f.Name()), slog.String("err", rerr.Error()))
		}
		return lockOutput{}, errors.Wrapf(err, "close %s", f.Name())
	}
	out.scratch = f.Name()
	return out, nil
}

// realDir returns dir as an absolute path with every symlink resolved.
func realDir(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", errors.Wrapf(err, "abs %s", dir)
	}
	return filepath.EvalSymlinks(abs)
}

// write writes lock to the scratch file as indented JSON and syncs it.
func (o lockOutput) write(lock Lock) error {
	f, err := os.OpenFile(o.scratch, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return errors.Wrapf(err, "open %s", o.scratch)
	}
	if err := json.MarshalWrite(f, lock, jsontext.WithIndent("  ")); err != nil {
		_ = f.Close()
		return errors.Wrap(err, "marshal lock")
	}
	if _, err := f.WriteString("\n"); err != nil {
		_ = f.Close()
		return errors.Wrapf(err, "write %s", o.scratch)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return errors.Wrapf(err, "sync %s", o.scratch)
	}
	if err := f.Close(); err != nil {
		return errors.Wrapf(err, "close %s", o.scratch)
	}
	if err := os.Chmod(o.scratch, o.mode); err != nil {
		return errors.Wrapf(err, "chmod %s", o.scratch)
	}
	return nil
}

// readLock reads and validates the lock at path, or from stdin for "-".
func readLock(path string) (Lock, error) {
	if path == "-" {
		l, err := ReadLock(os.Stdin)
		if err != nil {
			return Lock{}, errors.Wrap(err, "read stdin")
		}
		return l, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return Lock{}, errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()
	l, err := ReadLock(f)
	if err != nil {
		return Lock{}, errors.Wrapf(err, "read %s", path)
	}
	return l, nil
}

// checkout pulls one source's dotgit into workdir with the tree of the lock
// commit written out, checks that the commit is on the source's branch, and
// stamps datasource.json with the commit and its author date. A source
// without a commit takes the head of its branch. It returns the repository
// root, the source ID datasource.json declares and the commit.
//
// The branch is checked after the tree is written, as pkg/dotgit checks a
// commit out only as part of a pull. A commit that is not in the dotgit
// already fails the pull, so only one that is there but off the branch
// costs a tree write.
func checkout(workdir string, s Source) (string, sourceTypes.SourceID, string, error) {
	ref, err := remote.NewRepository(s.Repository)
	if err != nil {
		return "", "", "", errors.Wrapf(err, "parse %s", s.Repository)
	}
	root := filepath.Join(workdir, ref.Reference.Registry, ref.Reference.Repository, ref.Reference.Reference)

	// A source without a commit is checked out at its branch, which pull
	// switches to when refs/heads/<branch> exists, and its commit is read
	// back from that ref. When the branch is missing, pull falls back to a
	// tag or a commit of that name, which the ref does not resolve to.
	checkoutAt, revision, at := s.Commit, s.Commit, s.Commit
	if s.Commit == "" {
		checkoutAt, revision, at = s.Branch, fmt.Sprintf("refs/heads/%s", s.Branch), fmt.Sprintf("the head of branch %s", s.Branch)
	}

	slog.Info("Pull", slog.String("name", s.Name), slog.String("repository", s.Repository), slog.String("branch", s.Branch), slog.String("commit", s.Commit))
	start := time.Now()
	if err := pull.Pull(s.Repository, pull.WithDir(workdir), pull.WithCheckout(checkoutAt), pull.WithRestore(true)); err != nil {
		return "", "", "", errors.Wrapf(err, "pull %s at %s", s.Repository, at)
	}
	c, err := show.Show(root, revision)
	if err != nil {
		return "", "", "", errors.Wrapf(err, "show %s in %s", revision, s.Repository)
	}
	// A pinned commit is checked as the lock spells it, so that a hash
	// which only resolves to a commit, such as an annotated tag's, is
	// refused rather than built at that commit.
	commit := s.Commit
	if commit == "" {
		commit = c.Hash
	}
	if err := contains.Contains(root, commit, contains.WithBranch(s.Branch)); err != nil {
		return "", "", "", errors.Wrapf(err, "check %s is on %s in %s", commit, s.Branch, s.Repository)
	}
	id, err := stampDataSource(filepath.Join(root, "datasource.json"), commit, c.AuthorTime)
	if err != nil {
		return "", "", "", errors.Wrap(err, "stamp datasource.json")
	}
	slog.Info("Pulled", slog.String("name", s.Name), slog.String("id", string(id)), slog.String("commit", commit), slog.Duration("elapsed", time.Since(start).Round(time.Millisecond)))

	return root, id, commit, nil
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
// lock: every source is there under the ID its datasource.json declared
// (ids, in lock order), at the lock commit, and nothing else is.
func verify(options *options, dbpath string, lock Lock, ids []sourceTypes.SourceID) error {
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

	seen := make(map[sourceTypes.SourceID]string, len(lock.Sources))
	for i, src := range lock.Sources {
		id := ids[i]
		if prev, ok := seen[id]; ok {
			return errors.Errorf("%s and %s both have datasource id %q", prev, src.Name, id)
		}
		seen[id] = src.Name

		ds, ok := byID[id]
		if !ok {
			return errors.Errorf("%s: datasource %q is not in the db", src.Name, id)
		}
		if ds.Extracted == nil || ds.Extracted.Commit != src.Commit {
			return errors.Errorf("%s: datasource %q has commit %q, lock has %q", src.Name, id, func() string {
				if ds.Extracted == nil {
					return ""
				}
				return ds.Extracted.Commit
			}(), src.Commit)
		}
	}
	if len(byID) != len(lock.Sources) {
		return errors.Errorf("db has %d datasources, lock has %d", len(byID), len(lock.Sources))
	}

	return nil
}
