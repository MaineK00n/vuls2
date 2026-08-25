package util_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/errors"

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

func TestDetectStreaming(t *testing.T) {
	ecosystem := ecosystemTypes.Ecosystem(fmt.Sprintf("%s:8", ecosystemTypes.EcosystemTypeAlma))

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

		// The early break blocks until the pipeline has quiesced, so the
		// fetch count must already be final the moment the range exits — no
		// background goroutine may touch the storage after the iterator
		// returns.
		calls := st.callCount()
		if again := st.waitQuiesce(t); again != calls {
			t.Errorf("fetches continued after the iterator returned: %d -> %d", calls, again)
		}
		// And it must be far below the root count: pre-break churn is
		// bounded by the result buffer plus blocked sends plus in-flight
		// workers, all O(concurrency).
		if bound := 6 * concurrency; calls > bound {
			t.Errorf("cancellation did not stop scheduling: %d of %d roots fetched (bound %d)", calls, nRoots, bound)
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

	t.Run("worker error is yielded, terminal, and stops production", func(t *testing.T) {
		const (
			nRoots      = 64
			concurrency = 2
		)
		st := newStubStorage(nRoots)
		st.detErr = dbTypes.ErrNotFoundDetection

		var produced atomic.Int64
		countingRequestFn := func(rootID dataTypes.RootID, names []string) util.Request {
			produced.Add(1)
			return stubRequestFn(rootID, names)
		}

		var (
			items int
			got   error
		)
		for rd, err := range util.Detect(st, ecosystem, []string{"stub"}, countingRequestFn, concurrency) {
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
		// The first worker error cancels the group context, which the
		// request producer watches too: it must stop building requests for
		// the remaining roots instead of churning through all of them.
		if p := produced.Load(); p >= nRoots {
			t.Errorf("producer built requests for all %d roots after the failure", p)
		}
	})
}

// stubStorage is a minimal session.Storage for streaming-semantics tests:
// GetIndex returns a fixed root set and GetDetection counts its calls.
// Every other method panics via the embedded nil interface.
type stubStorage struct {
	session.Storage

	roots  []dataTypes.RootID
	detErr error

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
	if st.detErr != nil {
		return nil, st.detErr
	}
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
