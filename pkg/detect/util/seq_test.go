package util_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
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
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	"github.com/MaineK00n/vuls2/pkg/detect/util"
)

func TestDetectStreaming(t *testing.T) {
	ecosystem := ecosystemTypes.Ecosystem(fmt.Sprintf("%s:8", ecosystemTypes.EcosystemTypeAlma))

	t.Run("full consumption yields every root's detection exactly once", func(t *testing.T) {
		const (
			nRoots      = 8
			concurrency = 3
		)
		st := newStubStorage(nRoots)

		got, err := test.CollectDetections(util.Detect(st, ecosystem, []string{"stub"}, stubRequestFn, concurrency))
		if err != nil {
			t.Fatalf("Detect. error = %v", err)
		}

		want := make(map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection, nRoots)
		for i := range nRoots {
			want[dataTypes.RootID(fmt.Sprintf("STUB-%04d", i))] = detectTypes.VulnerabilityDataDetection{
				Ecosystem: ecosystem,
				Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
					sourceTypes.SourceID("stub-source"): {{
						Criteria: criteriaTypes.FilteredCriteria{
							Operator: criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: []criterionTypes.FilteredCriterion{{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: vcPackageTypes.Package{
											Type:   vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{Name: "stub-pkg"},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
							}},
						},
					}},
				},
			}
		}
		if diff := gocmp.Diff(want, got); diff != "" {
			t.Errorf("collected detections (-expected +got):\n%s", diff)
		}
		if calls := st.callCount(); calls != nRoots {
			t.Errorf("fetch count = %d, want %d (each root fetched exactly once)", calls, nRoots)
		}
	})

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

	t.Run("workers blocked on a full result buffer escape on early break", func(t *testing.T) {
		// Deterministically construct the deadlock-candidate state: consume
		// one element, then park inside the loop body until the fetch count
		// quiesces. With the consumer not receiving, the pipeline wedges at
		// exactly 2*concurrency+1 fetches — concurrency+1 results delivered
		// (buffer cap + the consumed element) plus concurrency workers
		// blocked on their resChan send. Breaking then joins the pipeline
		// (<-done), so this subtest completing at all proves the blocked
		// senders escaped via gctx.Done — with that select arm removed, it
		// deadlocks.
		const (
			nRoots      = 64
			concurrency = 2
		)
		st := newStubStorage(nRoots)

		n := 0
		var wedged int
		for _, err := range util.Detect(st, ecosystem, []string{"stub"}, stubRequestFn, concurrency) {
			if err != nil {
				t.Fatalf("Detect. error = %v", err)
			}
			n++
			wedged = st.waitQuiesce(t)
			break
		}
		if n != 1 {
			t.Fatalf("expected exactly one element before break, got %d", n)
		}
		if want := 2*concurrency + 1; wedged != want {
			t.Errorf("wedged fetch count = %d, want %d (buffer+consumed+blocked senders)", wedged, want)
		}
		if again := st.waitQuiesce(t); again != wedged {
			t.Errorf("fetches continued after the iterator returned: %d -> %d", wedged, again)
		}
	})

	t.Run("a panic in the consumer's loop body still joins the pipeline", func(t *testing.T) {
		// The join runs in a defer, so even a panic unwinding through yield
		// must leave no worker inside the storage by the time the panic
		// escapes the range. The call count cannot pin this (a worker still
		// inside GetDetection has already been counted), so the stub keeps
		// an in-flight gauge and a fetch delay wide enough that, without
		// the join, the panic escapes while workers are still mid-fetch.
		const (
			nRoots      = 64
			concurrency = 2
		)
		st := newStubStorage(nRoots)
		st.fetchDelay = 100 * time.Millisecond

		func() {
			defer func() {
				if r := recover(); r != "consumer loop body" {
					t.Fatalf("expected the consumer panic to propagate, recovered %v", r)
				}
			}()
			for range util.Detect(st, ecosystem, []string{"stub"}, stubRequestFn, concurrency) {
				// Make sure at least one worker is provably mid-fetch when
				// the panic fires.
				for st.inFlight.Load() == 0 {
					time.Sleep(time.Millisecond)
				}
				panic("consumer loop body")
			}
		}()

		if n := st.inFlight.Load(); n != 0 {
			t.Errorf("%d workers still inside GetDetection after the panic escaped the range", n)
		}
		calls := st.callCount()
		if again := st.waitQuiesce(t); again != calls {
			t.Errorf("fetches continued after the panic escaped: %d -> %d", calls, again)
		}
		if bound := 6 * concurrency; calls > bound {
			t.Errorf("cancellation did not stop scheduling: %d of %d roots fetched (bound %d)", calls, nRoots, bound)
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

	mu         sync.Mutex
	calls      int
	inFlight   atomic.Int32
	fetchDelay time.Duration
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
	st.inFlight.Add(1)
	defer st.inFlight.Add(-1)
	st.mu.Lock()
	st.calls++
	st.mu.Unlock()
	// An opt-in delay keeps workers measurably inside the fetch, so tests
	// can observe whether the iterator joined them before returning.
	if st.fetchDelay > 0 {
		time.Sleep(st.fetchDelay)
	}
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
