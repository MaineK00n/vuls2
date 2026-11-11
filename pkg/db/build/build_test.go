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
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	ts := httptest.NewTLSServer(containerregistry.New())
	defer ts.Close()

	originalTransport := http.DefaultTransport
	http.DefaultTransport = ts.Client().Transport
	defer func() {
		http.DefaultTransport = originalTransport
	}()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	registry := fmt.Sprintf("%s/vulsio/vuls-data-db", u.Host)

	alpha := newExtracted(t, "alpha", "alpha", 2)
	beta := newExtracted(t, "beta", "beta", 1)
	gamma := newExtracted(t, "gamma", "gamma", 1)
	// delta declares alpha's datasource id: adding both must fail.
	delta := newExtracted(t, "delta", "alpha", 1)
	for name, e := range map[string]extracted{"alpha": alpha, "beta": beta, "gamma": gamma, "delta": delta} {
		pushExtracted(t, registry, name, e.dir)
	}

	// runBuild writes lock to a file, runs Build on it and fails the test if
	// it does not return in time, so a scheduling bug shows up as a failure
	// rather than a hung test.
	runBuild := func(t *testing.T, lock build.Lock, opts ...build.Option) error {
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

	t.Run("build", func(t *testing.T) {
		dbpath := filepath.Join(t.TempDir(), "vuls.db")
		reportPath := filepath.Join(t.TempDir(), "report.json")
		lock := build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
			{Name: "alpha", Commit: alpha.nightly[0]},
			{Name: "beta", Commit: beta.nightly[0]},
		}}

		if err := runBuild(t, lock, build.WithDBPath(dbpath), build.WithDownloadConcurrency(2), build.WithReport(reportPath), build.WithDir(filepath.Join(t.TempDir(), "work"))); err != nil {
			t.Fatalf("Build() error = %v", err)
		}

		if _, err := os.Stat(dbpath); err != nil {
			t.Errorf("db not built: %v", err)
		}
		assertNoScratch(t, dbpath)

		dss := datasources(t, dbpath)
		if len(dss) != 2 {
			t.Fatalf("datasources = %d, want 2", len(dss))
		}
		if got := dss["alpha"].Extracted.Commit; got != alpha.nightly[0] {
			t.Errorf("alpha commit = %s, want %s", got, alpha.nightly[0])
		}
		if got := dss["alpha"].Extracted.Date; got == nil || !got.Equal(commitDate(1)) {
			t.Errorf("alpha date = %v, want %v", got, commitDate(1))
		}
		// alpha is pinned one commit behind nightly: the tree that was
		// restored and added must be the pinned commit's, not the head's.
		if got := dss["alpha"].Name; got == nil || *got != "alpha 1" {
			t.Errorf("alpha name = %v, want %q (the pinned commit's datasource.json)", got, "alpha 1")
		}
		if got := dss["beta"].Extracted.Commit; got != beta.nightly[0] {
			t.Errorf("beta commit = %s, want %s", got, beta.nightly[0])
		}

		report := readReport(t, reportPath)
		if report.Branch != "nightly" || report.Registry != registry {
			t.Errorf("report branch = %q registry = %q, want %q %q", report.Branch, report.Registry, "nightly", registry)
		}
		if len(report.Sources) != 2 {
			t.Fatalf("report sources = %d, want 2", len(report.Sources))
		}
		a := report.Sources[0]
		if a.Name != "alpha" || a.ID != sourceTypes.SourceID("alpha") || a.Commit != alpha.nightly[0] {
			t.Errorf("report[0] = %+v", a)
		}
		if a.Behind != 1 || a.NextCommit != alpha.nightly[1] || a.BranchHead != alpha.nightly[1] {
			t.Errorf("alpha behind = %d next = %s head = %s, want 1 %s %s", a.Behind, a.NextCommit, a.BranchHead, alpha.nightly[1], alpha.nightly[1])
		}
		if a.NextCommitDate == nil || !a.NextCommitDate.Equal(commitDate(2)) || !a.CommitDate.Equal(commitDate(1)) {
			t.Errorf("alpha dates: commit %v next %v, want %v %v", a.CommitDate, a.NextCommitDate, commitDate(1), commitDate(2))
		}
		b := report.Sources[1]
		if b.Name != "beta" || b.Behind != 0 || b.NextCommit != "" || b.NextCommitDate != nil || b.BranchHead != beta.nightly[0] {
			t.Errorf("report[1] = %+v", b)
		}
		if !strings.HasPrefix(report.VulsVersion, "vuls ") {
			t.Errorf("vuls version = %q", report.VulsVersion)
		}
		for _, r := range report.Sources {
			if r.PullSeconds <= 0 || r.RestoreSeconds <= 0 || r.AddSeconds <= 0 {
				t.Errorf("%s: stage timings not recorded: pull %v restore %v add %v", r.Name, r.PullSeconds, r.RestoreSeconds, r.AddSeconds)
			}
		}
	})

	t.Run("more sources than slots", func(t *testing.T) {
		// With fewer download or tree slots than sources, every source must
		// still get through, and the report must still list the sources in
		// lock order whatever order they were added in.
		tests := []struct {
			name     string
			download int
			restore  int
		}{
			{name: "download 1, restore 1", download: 1, restore: 1},
			{name: "download 2, restore 1", download: 2, restore: 1},
			{name: "download 1, restore 2", download: 1, restore: 2},
			{name: "download 3, restore 3", download: 3, restore: 3},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				dbpath := filepath.Join(t.TempDir(), "vuls.db")
				reportPath := filepath.Join(t.TempDir(), "report.json")
				lock := build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
					{Name: "alpha", Commit: alpha.nightly[1]},
					{Name: "beta", Commit: beta.nightly[0]},
					{Name: "gamma", Commit: gamma.nightly[0]},
				}}
				if err := runBuild(t, lock, build.WithDBPath(dbpath), build.WithDownloadConcurrency(tt.download), build.WithRestoreConcurrency(tt.restore), build.WithReport(reportPath), build.WithDir(filepath.Join(t.TempDir(), "work"))); err != nil {
					t.Fatalf("Build() error = %v", err)
				}
				report := readReport(t, reportPath)
				if got := []string{report.Sources[0].Name, report.Sources[1].Name, report.Sources[2].Name}; strings.Join(got, ",") != "alpha,beta,gamma" {
					t.Errorf("order = %v", got)
				}
				if dss := datasources(t, dbpath); len(dss) != 3 {
					t.Errorf("datasources = %d, want 3", len(dss))
				}
			})
		}
	})

	t.Run("existing db or report is refused", func(t *testing.T) {
		// Nothing is overwritten: a db or report path that already exists
		// (also as a dangling symlink) stops the build before any work.
		lock := build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
			{Name: "beta", Commit: beta.nightly[0]},
		}}
		tests := []struct {
			name     string
			existing string
			report   bool
			symlink  bool
		}{
			{name: "db", existing: "vuls.db"},
			{name: "report", existing: "report.json", report: true},
			{name: "report as a dangling symlink", existing: "report.json", report: true, symlink: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				dir := t.TempDir()
				dbpath := filepath.Join(dir, "vuls.db")
				reportPath := filepath.Join(dir, "report.json")
				existing := filepath.Join(dir, tt.existing)
				if tt.symlink {
					if err := os.Symlink(filepath.Join(dir, "nowhere"), existing); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
				work := filepath.Join(t.TempDir(), "work")

				err := runBuild(t, lock, build.WithDBPath(dbpath), build.WithReport(reportPath), build.WithDir(work))
				if err == nil || !strings.Contains(err.Error(), "already exists") {
					t.Fatalf("Build() error = %v, want already exists", err)
				}
				if !tt.symlink {
					if bs, err := os.ReadFile(existing); err != nil || string(bs) != "keep" {
						t.Errorf("%s changed: %q, %v", existing, bs, err)
					}
				}
				if !tt.report {
					assertNoScratch(t, dbpath)
				}
				if _, err := os.Stat(work); !os.IsNotExist(err) {
					t.Errorf("work directory created before the check: %v", err)
				}
			})
		}
	})

	t.Run("work directory is removed after a failed add", func(t *testing.T) {
		// delta carries alpha's id, so its add fails after alpha's succeeded
		// and after later sources may already have been pulled.
		dbpath := filepath.Join(t.TempDir(), "vuls.db")
		dir := filepath.Join(t.TempDir(), "work")
		lock := build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
			{Name: "alpha", Commit: alpha.nightly[1]},
			{Name: "delta", Commit: delta.nightly[0]},
			{Name: "beta", Commit: beta.nightly[0]},
		}}
		if err := runBuild(t, lock, build.WithDBPath(dbpath), build.WithDownloadConcurrency(3), build.WithRestoreConcurrency(2), build.WithDir(dir)); err == nil {
			t.Fatal("Build() error = nil, want duplicate datasource")
		}
		if _, err := os.Stat(dbpath); !os.IsNotExist(err) {
			t.Errorf("db written despite failure: %v", err)
		}
		assertNoScratch(t, dbpath)
		assertEmptyDir(t, dir)
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
		lock := build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
			{Name: "alpha", Commit: alpha.nightly[0]},
			{Name: "beta", Commit: beta.nightly[0]},
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

	t.Run("lock the registry cannot satisfy", func(t *testing.T) {
		tests := []struct {
			name    string
			lock    build.Lock
			wantErr string
		}{
			{
				name: "commit outside the branch",
				lock: build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
					{Name: "alpha", Commit: alpha.stray},
				}},
				wantErr: "not an ancestor",
			},
			{
				name: "commit missing from the repository",
				lock: build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
					{Name: "alpha", Commit: "0123456789abcdef0123456789abcdef01234567"},
				}},
				wantErr: "history truncated or rewritten",
			},
			{
				name: "unknown branch",
				lock: build.Lock{Branch: "release", Registry: registry, Sources: []build.Source{
					{Name: "alpha", Commit: alpha.nightly[0]},
				}},
				wantErr: "branch release is not in",
			},
			{
				name: "missing repository",
				lock: build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
					{Name: "zeta", Commit: alpha.nightly[0]},
				}},
				wantErr: "pull",
			},
			{
				// The other sources are cancelled by the failure; the error
				// returned must be the failure, not their cancellation.
				name: "missing repository among others",
				lock: build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
					{Name: "alpha", Commit: alpha.nightly[0]},
					{Name: "beta", Commit: beta.nightly[0]},
					{Name: "zeta", Commit: alpha.nightly[0]},
					{Name: "gamma", Commit: gamma.nightly[0]},
				}},
				wantErr: "download zeta",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := runBuild(t, tt.lock, build.WithDBPath(filepath.Join(t.TempDir(), "vuls.db")), build.WithDir(filepath.Join(t.TempDir(), "work")))
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Build() error = %v, want %q", err, tt.wantErr)
				}
			})
		}
	})

	t.Run("report that reaches the db is refused after the db is in place", func(t *testing.T) {
		// Neither path exists at the start, so the existence check passes;
		// the db is renamed into place first and the exclusive create of the
		// report then fails on it, whatever route the report path takes.
		lock := build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
			{Name: "beta", Commit: beta.nightly[0]},
		}}
		tests := []struct {
			name   string
			report func(dir string) string
		}{
			{
				name: "symlinked parent",
				report: func(dir string) string {
					alias := filepath.Join(t.TempDir(), "alias")
					if err := os.Symlink(dir, alias); err != nil {
						t.Fatal(err)
					}
					return filepath.Join(alias, "vuls.db")
				},
			},
			{
				name: "symlink followed by ..",
				report: func(dir string) string {
					sub := filepath.Join(dir, "sub")
					if err := os.Mkdir(sub, 0o755); err != nil {
						t.Fatal(err)
					}
					alias := filepath.Join(t.TempDir(), "alias")
					if err := os.Symlink(sub, alias); err != nil {
						t.Fatal(err)
					}
					return fmt.Sprintf("%s/../vuls.db", alias)
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				dir := t.TempDir()
				dbpath := filepath.Join(dir, "vuls.db")
				err := runBuild(t, lock, build.WithDBPath(dbpath), build.WithReport(tt.report(dir)), build.WithDir(filepath.Join(t.TempDir(), "work")))
				if err == nil || !strings.Contains(err.Error(), "write report") {
					t.Fatalf("Build() error = %v, want write report refused", err)
				}
				if dss := datasources(t, dbpath); len(dss) != 1 {
					t.Errorf("db at %s has %d datasources, want 1 (replaced by the report?)", dbpath, len(dss))
				}
			})
		}
	})
}

// commitDate is the author date of the n-th commit newExtracted makes.
func commitDate(n int) time.Time {
	return time.Date(2026, 1, n, 0, 0, 0, 0, time.UTC)
}

func TestBuild_ValidateOnly(t *testing.T) {
	tests := []struct {
		name    string
		lock    string
		wantErr bool
	}{
		{
			// The registry does not exist: validate-only must not reach it.
			name: "valid lock",
			lock: `{
				"branch": "nightly",
				"registry": "127.0.0.1:1/vulsio/vuls-data-db",
				"sources": [
					{"name": "alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
		},
		{
			name: "invalid lock",
			lock: `{
				"branch": "nightly~1",
				"registry": "127.0.0.1:1/vulsio/vuls-data-db",
				"sources": [
					{"name": "alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lockPath := filepath.Join(t.TempDir(), "lock.json")
			if err := os.WriteFile(lockPath, []byte(tt.lock), 0o600); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			dbpath := filepath.Join(dir, "vuls.db")
			if err := build.Build(lockPath, build.WithValidateOnly(true), build.WithDBPath(dbpath), build.WithDir(filepath.Join(dir, "work"))); (err != nil) != tt.wantErr {
				t.Fatalf("Build() error = %v, wantErr %v", err, tt.wantErr)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) > 0 {
				t.Errorf("validate-only created files: %v", entries)
			}
		})
	}
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

// readReport reads the JSON report a build wrote to path.
func readReport(t *testing.T, path string) build.Report {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open report: %v", err)
	}
	defer f.Close()
	var r build.Report
	if err := json.UnmarshalRead(f, &r); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	return r
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
