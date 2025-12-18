package test

import (
	"errors"
	"os"
	"path/filepath"

	dbAdd "github.com/MaineK00n/vuls2/pkg/db/add"
	db "github.com/MaineK00n/vuls2/pkg/db/common"
	dbInit "github.com/MaineK00n/vuls2/pkg/db/init"
)

// PopulateDB populates the database specified by c with test data from fixtureDir.
// Children of fixtureDir are datasource directories, each has "datasource.json" file and "data/" directory.
func PopulateDB(c db.Config, fixtureDir string) error {
	if c.Path == "" { // fool proof
		return errors.New("Config.Path must not be empty")
	}

	if fixtureDir == "" { // fool proof
		return errors.New("fixtureDir must not be empty")
	}

	if err := dbInit.Init(dbInit.WithDBType(c.Type), dbInit.WithDBPath(c.Path), dbInit.WithDBOptions(c.Options), dbInit.WithDebug(c.Debug)); err != nil {
		return err
	}

	datasources, err := os.ReadDir(fixtureDir)
	if err != nil {
		return err
	}

	for _, ds := range datasources {
		if err := dbAdd.Add(filepath.Join(fixtureDir, ds.Name()), dbAdd.WithDBType(c.Type), dbAdd.WithDBPath(c.Path), dbAdd.WithDBOptions(c.Options), dbAdd.WithDebug(c.Debug)); err != nil {
			return err
		}
	}

	return nil
}
