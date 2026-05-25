package test

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
)

// PopulateDB populates the database specified by c with test data from fixtureDir.
// Children of fixtureDir are datasource directories, each has "datasource.json" file and "data/" directory.
func PopulateDB(c session.Config, fixtureDir string) error {
	if c.Path == "" { // fool proof
		return errors.New("Config.Path must not be empty")
	}

	if fixtureDir == "" { // fool proof
		return errors.New("fixtureDir must not be empty")
	}

	s, err := c.New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}

	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer s.Storage().Close()

	if err := s.Storage().Initialize(); err != nil {
		return errors.Wrap(err, "initialize")
	}

	datasources, err := os.ReadDir(fixtureDir)
	if err != nil {
		return err
	}

	for _, ds := range datasources {
		if err := s.Storage().Put(filepath.Join(fixtureDir, ds.Name())); err != nil {
			return errors.Wrapf(err, "put %s", ds.Name())
		}
	}

	return nil
}

// FilterAffected mirrors the top-level per-condition Affected gate applied
// in pkg/detect.Detect. Lower-level Detect functions (ospkg, cpe, util) now
// pass every condition through unconditionally, so tests that previously
// asserted only the affected subset use this helper to reproduce the
// filtered view.
func FilterAffected(t require, in map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection) map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection {
	if in == nil {
		return nil
	}
	out := make(map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection, len(in))
	for rootID, d := range in {
		keptContents := make(map[sourceTypes.SourceID][]conditionTypes.FilteredCondition)
		for sid, conds := range d.Contents {
			kept := make([]conditionTypes.FilteredCondition, 0, len(conds))
			for _, cond := range conds {
				ok, err := cond.Criteria.Affected()
				if err != nil {
					t.Fatalf("criteria affected (rootID: %s): %v", rootID, err)
				}
				if ok {
					kept = append(kept, cond)
				}
			}
			if len(kept) > 0 {
				keptContents[sid] = kept
			}
		}
		if len(keptContents) == 0 {
			continue
		}
		d.Contents = keptContents
		out[rootID] = d
	}
	return out
}

// require is a tiny subset of testing.TB so this helper can stay decoupled
// from the testing package while still surfacing fatal errors to the caller.
type require interface {
	Fatalf(format string, args ...any)
}
