package test

import (
	"iter"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	"github.com/MaineK00n/vuls2/pkg/detect/util"
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

// CollectDetections accumulates a detection stream into a map, stopping at
// the first yielded error — the test-side counterpart of what a
// whole-result consumer does with the streaming Detect APIs.
func CollectDetections(seq iter.Seq2[util.RootDetection, error]) (map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection, error) {
	dm := make(map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection)
	for rd, err := range seq {
		if err != nil {
			return nil, err
		}
		dm[rd.RootID] = rd.Detection
	}
	return dm, nil
}
