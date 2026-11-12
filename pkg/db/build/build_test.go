package build_test

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	containerregistry "github.com/google/go-containerregistry/pkg/registry"
	bolt "go.etcd.io/bbolt"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/compress"
	registryPush "github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/push"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

	"github.com/MaineK00n/vuls2/pkg/db/build"
	"github.com/MaineK00n/vuls2/pkg/db/session"
)

// extracted is a test extracted repository: commits on nightly oldest first,
// plus one commit on another branch that nightly does not contain.
type extracted struct {
	dir     string
	nightly []string
	stray   string
}

func TestBuild(t *testing.T) {
	f := newFixture(t)

	// dataSource is what the db holds for one source: the commit and date
	// it records, and the name of its datasource.json. newExtracted names
	// the n-th commit's datasource "<source> <n>", so the name tells which
	// commit's tree was added.
	type dataSource struct {
		Commit string
		Date   time.Time
		Name   string
	}

	tests := []struct {
		name    string
		lock    build.Lock
		want    map[sourceTypes.SourceID]dataSource
		wantErr string
	}{
		{
			// The tree added must be the pinned commit's, not the head's.
			name: "source pinned behind the branch head",
			lock: build.Lock{Branch: "nightly", Registry: f.registry, Sources: []build.Source{
				{Name: "alpha", Commit: f.alpha.nightly[0]},
				{Name: "beta", Commit: f.beta.nightly[0]},
			}},
			want: map[sourceTypes.SourceID]dataSource{
				"alpha": {Commit: f.alpha.nightly[0], Date: commitDate(1), Name: "alpha 1"},
				"beta":  {Commit: f.beta.nightly[0], Date: commitDate(1), Name: "beta 1"},
			},
		},
		{
			name: "sources at the branch head",
			lock: build.Lock{Branch: "nightly", Registry: f.registry, Sources: []build.Source{
				{Name: "alpha", Commit: f.alpha.nightly[1]},
				{Name: "beta", Commit: f.beta.nightly[0]},
				{Name: "gamma", Commit: f.gamma.nightly[0]},
			}},
			want: map[sourceTypes.SourceID]dataSource{
				"alpha": {Commit: f.alpha.nightly[1], Date: commitDate(2), Name: "alpha 2"},
				"beta":  {Commit: f.beta.nightly[0], Date: commitDate(1), Name: "beta 1"},
				"gamma": {Commit: f.gamma.nightly[0], Date: commitDate(1), Name: "gamma 1"},
			},
		},
		{
			name: "commit outside the branch",
			lock: build.Lock{Branch: "nightly", Registry: f.registry, Sources: []build.Source{
				{Name: "alpha", Commit: f.alpha.stray},
			}},
			wantErr: "not an ancestor",
		},
		{
			name: "commit missing from the repository",
			lock: build.Lock{Branch: "nightly", Registry: f.registry, Sources: []build.Source{
				{Name: "alpha", Commit: "0123456789abcdef0123456789abcdef01234567"},
			}},
			wantErr: "history truncated or rewritten",
		},
		{
			name: "unknown branch",
			lock: build.Lock{Branch: "release", Registry: f.registry, Sources: []build.Source{
				{Name: "alpha", Commit: f.alpha.nightly[0]},
			}},
			wantErr: "branch release is not in",
		},
		{
			name: "missing repository",
			lock: build.Lock{Branch: "nightly", Registry: f.registry, Sources: []build.Source{
				{Name: "zeta", Commit: f.alpha.nightly[0]},
			}},
			wantErr: "pull",
		},
		{
			// The sources before the failure have been added to the scratch
			// db; it must not end up at dbpath.
			name: "missing repository after others",
			lock: build.Lock{Branch: "nightly", Registry: f.registry, Sources: []build.Source{
				{Name: "alpha", Commit: f.alpha.nightly[0]},
				{Name: "beta", Commit: f.beta.nightly[0]},
				{Name: "zeta", Commit: f.alpha.nightly[0]},
				{Name: "gamma", Commit: f.gamma.nightly[0]},
			}},
			wantErr: "download zeta",
		},
		{
			// delta carries alpha's id and comes after it in the lock.
			name: "duplicate datasource id",
			lock: build.Lock{Branch: "nightly", Registry: f.registry, Sources: []build.Source{
				{Name: "alpha", Commit: f.alpha.nightly[1]},
				{Name: "delta", Commit: f.delta.nightly[0]},
				{Name: "beta", Commit: f.beta.nightly[0]},
			}},
			wantErr: "add delta",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbpath := filepath.Join(t.TempDir(), "vuls.db")
			work := filepath.Join(t.TempDir(), "work")

			err := runBuild(t, tt.lock, build.WithDBPath(dbpath), build.WithDir(work))

			// However the build ends, no scratch db or extracted tree is
			// left behind.
			assertNoScratch(t, dbpath)
			assertEmptyDir(t, work)

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Build() error = %v, want %q", err, tt.wantErr)
				}
				if _, err := os.Lstat(dbpath); !os.IsNotExist(err) {
					t.Errorf("db written despite the failure: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}

			got := make(map[sourceTypes.SourceID]dataSource)
			for id, ds := range datasources(t, dbpath) {
				var d dataSource
				if ds.Extracted != nil {
					d.Commit = ds.Extracted.Commit
					if ds.Extracted.Date != nil {
						d.Date = *ds.Extracted.Date
					}
				}
				if ds.Name != nil {
					d.Name = *ds.Name
				}
				got[id] = d
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("datasources (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBuild_Paths(t *testing.T) {
	f := newFixture(t)

	t.Run("existing db is refused", func(t *testing.T) {
		// Nothing is overwritten: a db path that already exists (also as a
		// dangling symlink) stops the build before any work.
		lock := build.Lock{Branch: "nightly", Registry: f.registry, Sources: []build.Source{
			{Name: "beta", Commit: f.beta.nightly[0]},
		}}
		tests := []struct {
			name    string
			symlink bool
		}{
			{name: "file"},
			{name: "dangling symlink", symlink: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				dir := t.TempDir()
				dbpath := filepath.Join(dir, "vuls.db")
				if tt.symlink {
					if err := os.Symlink(filepath.Join(dir, "nowhere"), dbpath); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(dbpath, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
				work := filepath.Join(t.TempDir(), "work")

				err := runBuild(t, lock, build.WithDBPath(dbpath), build.WithDir(work))
				if err == nil || !strings.Contains(err.Error(), "already exists") {
					t.Fatalf("Build() error = %v, want already exists", err)
				}
				if !tt.symlink {
					if bs, err := os.ReadFile(dbpath); err != nil || string(bs) != "keep" {
						t.Errorf("%s changed: %q, %v", dbpath, bs, err)
					}
				}
				assertNoScratch(t, dbpath)
				if _, err := os.Stat(work); !os.IsNotExist(err) {
					t.Errorf("work directory created before the check: %v", err)
				}
			})
		}
	})

	t.Run("paths through a symlink and ..", func(t *testing.T) {
		// alias points to real/sub, so the kernel resolves alias/../x to
		// real/x while a lexical clean would give x next to alias.
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "real", "sub"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "real", "sub"), filepath.Join(root, "alias")); err != nil {
			t.Fatal(err)
		}
		lock := build.Lock{Branch: "nightly", Registry: f.registry, Sources: []build.Source{
			{Name: "alpha", Commit: f.alpha.nightly[0]},
			{Name: "beta", Commit: f.beta.nightly[0]},
		}}
		dbpath := fmt.Sprintf("%s/../vuls.db", filepath.Join(root, "alias"))
		dir := fmt.Sprintf("%s/../work", filepath.Join(root, "alias"))
		if err := runBuild(t, lock, build.WithDBPath(dbpath), build.WithDir(dir)); err != nil {
			t.Fatalf("Build() error = %v", err)
		}

		if _, err := os.Stat(filepath.Join(root, "real", "vuls.db")); err != nil {
			t.Errorf("db not at the resolved path: %v", err)
		}
		assertNoScratch(t, filepath.Join(root, "real", "vuls.db"))
		assertEmptyDir(t, filepath.Join(root, "real", "work"))
		for _, p := range []string{filepath.Join(root, "vuls.db"), filepath.Join(root, "work")} {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Errorf("%s created at the lexically cleaned path: %v", p, err)
			}
		}
		matches, err := filepath.Glob(filepath.Join(root, ".vuls.db.build-*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) > 0 {
			t.Errorf("scratch db created at the lexically cleaned path: %v", matches)
		}
	})

}

// fixture is a registry serving the extracted repositories the tests build
// from: alpha with two commits on nightly, beta and gamma with one each, and
// delta, which declares alpha's datasource id.
type fixture struct {
	registry                  string
	alpha, beta, gamma, delta extracted
}

// newFixture starts the registry and pushes the repositories to it. The
// registry is reached through http.DefaultTransport, which is swapped for
// the test server's until cleanup, so tests using it must not run in
// parallel.
func newFixture(t *testing.T) fixture {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	ts := httptest.NewTLSServer(containerregistry.New())
	t.Cleanup(ts.Close)

	originalTransport := http.DefaultTransport
	http.DefaultTransport = ts.Client().Transport
	t.Cleanup(func() {
		http.DefaultTransport = originalTransport
	})

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	f := fixture{
		registry: fmt.Sprintf("%s/vulsio/vuls-data-db", u.Host),
		alpha:    newExtracted(t, "alpha", "alpha", 2),
		beta:     newExtracted(t, "beta", "beta", 1),
		gamma:    newExtracted(t, "gamma", "gamma", 1),
		delta:    newExtracted(t, "delta", "alpha", 1),
	}
	for name, e := range map[string]extracted{"alpha": f.alpha, "beta": f.beta, "gamma": f.gamma, "delta": f.delta} {
		pushExtracted(t, f.registry, name, e.dir)
	}
	return f
}

// runBuild writes lock to a file, runs Build on it and fails the test if it
// does not return in time, so a scheduling bug shows up as a failure rather
// than a hung test.
func runBuild(t *testing.T, lock build.Lock, opts ...build.Option) error {
	t.Helper()
	lockPath := writeLock(t, lock)
	ch := make(chan error, 1)
	go func() {
		ch <- build.Build(lockPath, opts...)
	}()
	select {
	case err := <-ch:
		return err
	case <-time.After(2 * time.Minute):
		t.Fatal("Build() did not return in 2 minutes")
		return nil
	}
}

// commitDate is the author date of the n-th commit newExtracted makes.
func commitDate(n int) time.Time {
	return time.Date(2026, 1, n, 0, 0, 0, 0, time.UTC)
}

// writeLock writes lock as JSON to a file and returns its path.
func writeLock(t *testing.T, lock build.Lock) string {
	t.Helper()
	bs, err := json.Marshal(lock)
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	path := filepath.Join(t.TempDir(), "lock.json")
	if err := os.WriteFile(path, bs, 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	return path
}

// assertNoScratch fails if a scratch db of dbpath was left behind.
func assertNoScratch(t *testing.T, dbpath string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(dbpath), fmt.Sprintf(".%s.build-*", filepath.Base(dbpath))))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) > 0 {
		t.Errorf("scratch db left behind: %v", matches)
	}
}

// assertEmptyDir fails if the work directory still holds anything.
func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) > 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("%s not cleaned up: %v", dir, names)
	}
}

// newExtracted makes a repository shaped like vuls-data-extracted-<name>:
// datasource.json at the root declaring id, n commits on nightly (main at
// the same tip), and one stray commit on another branch.
func newExtracted(t *testing.T, name, id string, n int) extracted {
	t.Helper()

	dir := filepath.Join(t.TempDir(), fmt.Sprintf("vuls-data-extracted-%s", name))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(date time.Time, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), fmt.Sprintf("GIT_AUTHOR_DATE=%s", date.Format(time.RFC3339)), fmt.Sprintf("GIT_COMMITTER_DATE=%s", date.Format(time.RFC3339)), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		bs, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", cmd.String(), err, bs)
		}
		return strings.TrimSpace(string(bs))
	}

	run(commitDate(1), "init", "-q", "-b", "nightly")

	// datasource.json carries the commit number in its name, so the
	// datasource read back from the db tells which commit's tree was
	// restored and added.
	writeDataSource := func(i int) {
		t.Helper()
		ds := datasourceTypes.DataSource{
			ID:   sourceTypes.SourceID(id),
			Name: func() *string { s := fmt.Sprintf("%s %d", name, i); return &s }(),
		}
		bs, err := json.Marshal(ds)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "datasource.json"), bs, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	e := extracted{dir: dir}
	for i := 1; i <= n; i++ {
		writeDataSource(i)
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(fmt.Sprintf("%s %d\n", name, i)), 0o644); err != nil {
			t.Fatal(err)
		}
		run(commitDate(i), "add", "-A")
		run(commitDate(i), "commit", "-q", "-m", fmt.Sprintf("extract %d", i))
		e.nightly = append(e.nightly, run(commitDate(i), "rev-parse", "HEAD"))
	}
	run(commitDate(n), "branch", "main")

	run(commitDate(n+1), "switch", "-q", "-c", "stray", e.nightly[0])
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("stray\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(commitDate(n+1), "add", "-A")
	run(commitDate(n+1), "commit", "-q", "-m", "stray")
	e.stray = run(commitDate(n+1), "rev-parse", "HEAD")
	run(commitDate(n+1), "switch", "-q", "nightly")

	return e
}

// pushExtracted packs the repository's .git as a dotgit and pushes it to
// <registry>:vuls-data-extracted-<name>, the way vuls-data-db publishes.
func pushExtracted(t *testing.T, registry, name, dir string) {
	t.Helper()

	dotgit := filepath.Join(t.TempDir(), fmt.Sprintf("vuls-data-extracted-%s.tar.zst", name))
	if err := compress.Compress(dir, dotgit, compress.WithRoot(fmt.Sprintf("vuls-data-extracted-%s", name))); err != nil {
		t.Fatalf("compress %s: %v", name, err)
	}
	if err := registryPush.Push(fmt.Sprintf("%s:vuls-data-extracted-%s", registry, name), dotgit, "token", registryPush.WithForce(true)); err != nil {
		t.Fatalf("push %s: %v", name, err)
	}
}

func datasources(t *testing.T, dbpath string) map[sourceTypes.SourceID]datasourceTypes.DataSource {
	t.Helper()

	s, err := (&session.Config{Type: "boltdb", Path: dbpath, Options: session.StorageOptions{BoltDB: bolt.DefaultOptions}}).New()
	if err != nil {
		t.Fatalf("new db connection: %v", err)
	}
	if err := s.Storage().Open(); err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer s.Storage().Close()

	dss, err := s.Storage().GetDataSources()
	if err != nil {
		t.Fatalf("get datasources: %v", err)
	}
	m := make(map[sourceTypes.SourceID]datasourceTypes.DataSource, len(dss))
	for _, ds := range dss {
		m[ds.ID] = ds
	}
	return m
}
