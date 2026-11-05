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
	registry := u.Host + "/vulsio/vuls-data-db"

	alpha := newExtracted(t, "alpha", "alpha", 2)
	beta := newExtracted(t, "beta", "beta", 1)
	// gamma declares alpha's datasource id: adding both must fail.
	gamma := newExtracted(t, "gamma", "alpha", 1)
	for name, e := range map[string]extracted{"alpha": alpha, "beta": beta, "gamma": gamma} {
		pushExtracted(t, registry, name, e.dir)
	}

	t.Run("build", func(t *testing.T) {
		dbpath := filepath.Join(t.TempDir(), "vuls.db")
		reportPath := filepath.Join(t.TempDir(), "report.json")
		lock := build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
			{Name: "alpha", Commit: alpha.nightly[0]},
			{Name: "beta", Commit: beta.nightly[0]},
		}}

		report, err := build.Build(lock, build.WithDBPath(dbpath), build.WithParallel(2), build.WithReport(reportPath), build.WithDir(filepath.Join(t.TempDir(), "work")))
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}

		if _, err := os.Stat(dbpath); err != nil {
			t.Errorf("db not built: %v", err)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(dbpath), ".vuls.db.build")); !os.IsNotExist(err) {
			t.Errorf("scratch db left behind: %v", err)
		}

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
		if got := dss["beta"].Extracted.Commit; got != beta.nightly[0] {
			t.Errorf("beta commit = %s, want %s", got, beta.nightly[0])
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

		f, err := os.Open(reportPath)
		if err != nil {
			t.Fatalf("open report: %v", err)
		}
		defer f.Close()
		var written build.Report
		if err := json.UnmarshalRead(f, &written); err != nil {
			t.Fatalf("unmarshal report: %v", err)
		}
		if len(written.Sources) != 2 || written.Branch != "nightly" || written.Registry != registry {
			t.Errorf("written report = %+v", written)
		}
	})

	t.Run("existing db is kept when the build fails", func(t *testing.T) {
		dbpath := filepath.Join(t.TempDir(), "vuls.db")
		if err := os.WriteFile(dbpath, []byte("not a db"), 0o600); err != nil {
			t.Fatal(err)
		}
		lock := build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
			{Name: "alpha", Commit: strings.Repeat("0", 40)},
		}}
		if _, err := build.Build(lock, build.WithDBPath(dbpath), build.WithDir(filepath.Join(t.TempDir(), "work"))); err == nil {
			t.Fatal("Build() error = nil, want commit not found")
		}
		bs, err := os.ReadFile(dbpath)
		if err != nil || string(bs) != "not a db" {
			t.Errorf("existing db changed: %q, %v", bs, err)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(dbpath), ".vuls.db.build")); !os.IsNotExist(err) {
			t.Errorf("scratch db left behind: %v", err)
		}
	})

	t.Run("commit outside the branch", func(t *testing.T) {
		lock := build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
			{Name: "alpha", Commit: alpha.stray},
		}}
		_, err := build.Build(lock, build.WithDBPath(filepath.Join(t.TempDir(), "vuls.db")), build.WithDir(filepath.Join(t.TempDir(), "work")))
		if err == nil || !strings.Contains(err.Error(), "not an ancestor") {
			t.Fatalf("Build() error = %v, want not an ancestor", err)
		}
	})

	t.Run("unknown branch", func(t *testing.T) {
		lock := build.Lock{Branch: "release", Registry: registry, Sources: []build.Source{
			{Name: "alpha", Commit: alpha.nightly[0]},
		}}
		if _, err := build.Build(lock, build.WithDBPath(filepath.Join(t.TempDir(), "vuls.db")), build.WithDir(filepath.Join(t.TempDir(), "work"))); err == nil {
			t.Fatal("Build() error = nil, want unknown branch")
		}
	})

	t.Run("duplicate datasource id", func(t *testing.T) {
		lock := build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
			{Name: "alpha", Commit: alpha.nightly[1]},
			{Name: "gamma", Commit: gamma.nightly[0]},
		}}
		dbpath := filepath.Join(t.TempDir(), "vuls.db")
		if _, err := build.Build(lock, build.WithDBPath(dbpath), build.WithDir(filepath.Join(t.TempDir(), "work"))); err == nil {
			t.Fatal("Build() error = nil, want duplicate datasource")
		}
		if _, err := os.Stat(dbpath); !os.IsNotExist(err) {
			t.Errorf("db written despite failure: %v", err)
		}
	})

	t.Run("missing repository", func(t *testing.T) {
		lock := build.Lock{Branch: "nightly", Registry: registry, Sources: []build.Source{
			{Name: "delta", Commit: alpha.nightly[0]},
		}}
		if _, err := build.Build(lock, build.WithDBPath(filepath.Join(t.TempDir(), "vuls.db")), build.WithDir(filepath.Join(t.TempDir(), "work"))); err == nil {
			t.Fatal("Build() error = nil, want pull failure")
		}
	})
}

// commitDate is the author date of the n-th commit newExtracted makes.
func commitDate(n int) time.Time {
	return time.Date(2026, 1, n, 0, 0, 0, 0, time.UTC)
}

// newExtracted makes a repository shaped like vuls-data-extracted-<name>:
// datasource.json at the root declaring id, n commits on nightly (main at
// the same tip), and one stray commit on another branch.
func newExtracted(t *testing.T, name, id string, n int) extracted {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "vuls-data-extracted-"+name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(date time.Time, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE="+date.Format(time.RFC3339), "GIT_COMMITTER_DATE="+date.Format(time.RFC3339), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		bs, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", cmd.String(), err, bs)
		}
		return strings.TrimSpace(string(bs))
	}

	run(commitDate(1), "init", "-q", "-b", "nightly")
	ds := datasourceTypes.DataSource{
		ID:   sourceTypes.SourceID(id),
		Name: func() *string { s := name; return &s }(),
	}
	bs, err := json.Marshal(ds)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "datasource.json"), bs, 0o644); err != nil {
		t.Fatal(err)
	}

	e := extracted{dir: dir}
	for i := 1; i <= n; i++ {
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

	dotgit := filepath.Join(t.TempDir(), "vuls-data-extracted-"+name+".tar.zst")
	if err := compress.Compress(dir, dotgit, compress.WithRoot("vuls-data-extracted-"+name)); err != nil {
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
