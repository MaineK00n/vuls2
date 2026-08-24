package util_test

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
	"go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/MaineK00n/vuls2/pkg/detect/internal/test"
	"github.com/MaineK00n/vuls2/pkg/detect/util"
)

// almaRequestFn returns the createRequestFn used by the alma-small fixture
// tests: a version query hitting ALSA-2019:3708's Judy criterion.
func almaRequestFn(rootID dataTypes.RootID, _ []string) util.Request {
	switch rootID {
	case dataTypes.RootID("ALSA-2019:3708"):
		return util.Request{
			RootID: rootID,
			Query: criterionTypes.Query{
				Version: []vcTypes.Query{
					{
						Binary: &vcTypes.QueryBinary{
							Family:  ecosystemTypes.EcosystemTypeAlma,
							Name:    "mariadb-devel:10.3::Judy",
							Version: "1.0.5-18.module_el8.6.0+2867+72759d2f",
							Arch:    "i686",
						},
					},
				},
			},
			Indexes: []int{42},
		}
	default:
		return util.Request{}
	}
}

func newAlmaSession(t *testing.T) *session.Session {
	t.Helper()
	config := session.Config{
		Type:    "boltdb",
		Path:    filepath.Join(t.TempDir(), "vuls.db"),
		Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
	}
	if err := test.PopulateDB(config, "testdata/fixtures/alma-small"); err != nil {
		t.Fatalf("populate db. error = %v", err)
	}
	s, err := config.New()
	if err != nil {
		t.Fatalf("new session. error = %v", err)
	}
	t.Cleanup(func() { _ = s.Storage().Close() })
	if err := s.Storage().Open(); err != nil {
		t.Fatalf("open storage. error = %v", err)
	}
	return s
}

func TestDetectStreaming(t *testing.T) {
	ecosystem := ecosystemTypes.Ecosystem(fmt.Sprintf("%s:8", ecosystemTypes.EcosystemTypeAlma))
	queries := []string{"mariadb-devel:10.3::Judy"}

	t.Run("early break cancels pending work", func(t *testing.T) {
		// A fixture with a single matching root cannot tell an early break
		// from normal full consumption, so use a stub storage with many
		// roots and count the detection fetches: after breaking on the
		// first element, only the fetches already in flight around the
		// cancellation may complete — the remaining roots must never be
		// fetched.
		const (
			nRoots      = 64
			concurrency = 2
		)
		st := newStubStorage(nRoots)

		n := 0
		for rd, err := range util.Detect(st, ecosystem, []string{"stub"}, stubRequestFn, concurrency) {
			if err != nil {
				t.Fatalf("Detect. error = %v", err)
			}
			if rd.RootID == "" {
				t.Error("yielded element carries no rootID")
			}
			n++
			break
		}
		if n != 1 {
			t.Fatalf("expected exactly one element before break, got %d", n)
		}

		// Let the pipeline quiesce (workers mid-element are allowed to
		// finish), then require the fetch count to be far below the root
		// count and stable: pre-break churn is bounded by the result
		// buffer plus blocked sends plus in-flight workers, all O(concurrency).
		calls := st.waitQuiesce(t)
		if bound := 6 * concurrency; calls > bound {
			t.Errorf("cancellation did not stop scheduling: %d of %d roots fetched (bound %d)", calls, nRoots, bound)
		}
		if again := st.waitQuiesce(t); again != calls {
			t.Errorf("fetches continued after quiescence: %d -> %d", calls, again)
		}

		// The stub storage stays usable for a full pass afterwards.
		dm, err := test.CollectDetections(util.Detect(st, ecosystem, []string{"stub"}, stubRequestFn, concurrency))
		if err != nil {
			t.Fatalf("Detect after early break. error = %v", err)
		}
		if len(dm) != nRoots {
			t.Errorf("full pass after early break returned %d roots, want %d", len(dm), nRoots)
		}
	})

	t.Run("worker error is yielded and terminal", func(t *testing.T) {
		s := newAlmaSession(t)

		var (
			items int
			got   error
		)
		for rd, err := range util.Detect(s.Storage(), ecosystem, queries, func(rootID dataTypes.RootID, _ []string) util.Request {
			return util.Request{RootID: dataTypes.RootID("ROOTID-NOT-EXIST")}
		}, 2) {
			if err != nil {
				got = err
				continue
			}
			_ = rd
			items++
		}
		if got == nil {
			t.Fatal("expected an error from Detect, got none")
		}
		if !errors.Is(got, dbTypes.ErrNotFoundDetection) {
			t.Errorf("unexpected error: %v", got)
		}
		if items != 0 {
			t.Errorf("expected no successful items, got %d", items)
		}
	})
}

// stubStorage is a minimal session.Storage for streaming-semantics tests:
// GetIndex returns a fixed root set and GetDetection counts its calls.
// Every other method panics via the embedded nil interface.
type stubStorage struct {
	session.Storage

	roots []dataTypes.RootID

	mu    sync.Mutex
	calls int
}

func newStubStorage(n int) *stubStorage {
	st := &stubStorage{roots: make([]dataTypes.RootID, 0, n)}
	for i := range n {
		st.roots = append(st.roots, dataTypes.RootID(fmt.Sprintf("STUB-%04d", i)))
	}
	return st
}

func (st *stubStorage) GetIndex(ecosystemTypes.Ecosystem, string) ([]dataTypes.RootID, error) {
	return st.roots, nil
}

func (st *stubStorage) GetDetection(_ ecosystemTypes.Ecosystem, rootID dataTypes.RootID) (map[sourceTypes.SourceID][]conditionTypes.Condition, error) {
	st.mu.Lock()
	st.calls++
	st.mu.Unlock()
	return map[sourceTypes.SourceID][]conditionTypes.Condition{
		sourceTypes.SourceID("stub-source"): {{
			Criteria: criteriaTypes.Criteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.Criterion{{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						Package: vcPackageTypes.Package{
							Type:   vcPackageTypes.PackageTypeBinary,
							Binary: &vcBinaryPackageTypes.Package{Name: "stub-pkg"},
						},
					},
				}},
			},
		}},
	}, nil
}

func (st *stubStorage) callCount() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.calls
}

// waitQuiesce polls until the fetch count stays unchanged for a few
// consecutive samples and returns it.
func (st *stubStorage) waitQuiesce(t *testing.T) int {
	t.Helper()
	prev, stable := st.callCount(), 0
	for range 200 {
		time.Sleep(5 * time.Millisecond)
		c := st.callCount()
		if c == prev {
			stable++
			if stable >= 3 {
				return c
			}
			continue
		}
		prev, stable = c, 0
	}
	t.Fatalf("fetch count did not quiesce (last %d)", prev)
	return prev
}

func stubRequestFn(rootID dataTypes.RootID, _ []string) util.Request {
	return util.Request{
		RootID: rootID,
		Query: criterionTypes.Query{
			Version: []vcTypes.Query{{
				Binary: &vcTypes.QueryBinary{Name: "stub-pkg", Version: "1.0.0"},
			}},
		},
		Indexes: []int{0},
	}
}
