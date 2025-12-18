package test

import (
	"errors"
	"io/fs"
	"net/url"
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

	if err := dbInit.Init(dbInit.WithDBType(c.Type), dbInit.WithDBPath(c.Path), dbInit.WithDBOptions(c.Options), dbInit.WithDebug(c.Debug)); err != nil {
		return err
	}

	parent := filepath.Join(filepath.Dir(c.Path), "fixtures")
	if err := queryUnescapeFileTree(fixtureDir, parent); err != nil {
		return err
	}

	datasources, err := os.ReadDir(parent)
	if err != nil {
		return err
	}

	for _, ds := range datasources {
		if err := dbAdd.Add(filepath.Join(parent, ds.Name()), dbAdd.WithDBType(c.Type), dbAdd.WithDBPath(c.Path), dbAdd.WithDBOptions(c.Options), dbAdd.WithDebug(c.Debug)); err != nil {
			return err
		}
	}

	return nil
}

// queryUnescapeFileTree copies a file tree at fixturePath to a outdir directory by query-unescaping file names.
func queryUnescapeFileTree(fixturePath, outdir string) error {
	if err := os.MkdirAll(outdir, fs.ModePerm); err != nil {
		return err
	}

	if err := filepath.WalkDir(fixturePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(fixturePath, path)
		if err != nil {
			return err
		}
		unescaped, err := url.QueryUnescape(rel)
		if err != nil {
			return err
		}

		targetDir := filepath.Join(outdir, filepath.Dir(unescaped))
		if err := os.MkdirAll(targetDir, fs.ModePerm); err != nil {
			return err
		}
		if err := os.Link(path, filepath.Join(outdir, unescaped)); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}
