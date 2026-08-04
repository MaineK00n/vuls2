package util_test

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/MaineK00n/vuls2/pkg/detect/internal/test"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
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
	t.Cleanup(func() { s.Storage().Close() })
	if err := s.Storage().Open(); err != nil {
		t.Fatalf("open storage. error = %v", err)
	}
	return s
}

func TestDetectSeq(t *testing.T) {
	ecosystem := ecosystemTypes.Ecosystem(fmt.Sprintf("%s:8", ecosystemTypes.EcosystemTypeAlma))
	queries := []string{"mariadb-devel:10.3::Judy"}

	t.Run("matches Detect", func(t *testing.T) {
		s := newAlmaSession(t)

		want, err := util.Detect(s.Storage(), ecosystem, queries, almaRequestFn, 2)
		if err != nil {
			t.Fatalf("Detect. error = %v", err)
		}
		if len(want) == 0 {
			t.Fatal("Detect returned no detections; fixture assumption broken")
		}

		got := make(map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection)
		for rd, err := range util.DetectSeq(s.Storage(), ecosystem, queries, almaRequestFn, 2) {
			if err != nil {
				t.Fatalf("DetectSeq. error = %v", err)
			}
			if _, ok := got[rd.RootID]; ok {
				t.Errorf("rootID %s yielded twice", rd.RootID)
			}
			got[rd.RootID] = rd.Detection
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("DetectSeq (-Detect +DetectSeq):\n%s", diff)
		}
	})

	t.Run("early break cancels cleanly", func(t *testing.T) {
		s := newAlmaSession(t)

		n := 0
		for range util.DetectSeq(s.Storage(), ecosystem, queries, almaRequestFn, 2) {
			n++
			break
		}
		if n != 1 {
			t.Errorf("expected exactly one element before break, got %d", n)
		}
		// Reaching here without deadlock means the producer side unwound;
		// run another full pass on the same session to verify the storage
		// is still usable after the cancelled one.
		if _, err := util.Detect(s.Storage(), ecosystem, queries, almaRequestFn, 2); err != nil {
			t.Errorf("Detect after early break. error = %v", err)
		}
	})

	t.Run("worker error is yielded and terminal", func(t *testing.T) {
		s := newAlmaSession(t)

		var (
			items int
			got   error
		)
		for rd, err := range util.DetectSeq(s.Storage(), ecosystem, queries, func(rootID dataTypes.RootID, _ []string) util.Request {
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
			t.Fatal("expected an error from DetectSeq, got none")
		}
		if !errors.Is(got, dbTypes.ErrNotFoundDetection) {
			t.Errorf("unexpected error: %v", got)
		}
		if items != 0 {
			t.Errorf("expected no successful items, got %d", items)
		}
	})
}
