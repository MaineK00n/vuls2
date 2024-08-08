package scan

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
	"github.com/MaineK00n/vuls2/pkg/version"
)

type options struct {
	resultsDir string

	debug bool
}

type Option interface {
	apply(*options)
}

type resultsDirOption string

func (o resultsDirOption) apply(opts *options) {
	opts.resultsDir = string(o)
}

func WithResultsDir(resultsDir string) Option {
	return resultsDirOption(resultsDir)
}

type debugOption bool

func (o debugOption) apply(opts *options) {
	opts.debug = bool(o)
}

func WithDebug(debug bool) Option {
	return debugOption(debug)
}

func Scan(root string, opts ...Option) error {
	options := &options{
		resultsDir: filepath.Join(utilos.UserCacheDir(), "results"),
		debug:      false,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := os.RemoveAll(options.resultsDir); err != nil {
		return errors.Wrapf(err, "remove %s", options.resultsDir)
	}

	// <root>/<timestamp>/<name>.json -> <resultsDir>/<UUID>/<timestamp>/scan.json
	m := map[string][]string{}
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		dir, file := filepath.Split(path)
		m[file] = append(m[file], filepath.Base(dir))

		return nil
	}); err != nil {
		return errors.WithStack(err)
	}

	for name, ts := range m {
		id, err := uuid.NewRandom()
		if err != nil {
			return errors.Wrap(err, "new UUID v4")
		}
		for _, t := range ts {
			if err := func() error {
				f, err := os.Open(filepath.Join(root, t, name))
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(root, t, name))
				}
				defer f.Close()

				var old scanResult
				if err := json.NewDecoder(f).Decode(&old); err != nil {
					return errors.Wrapf(err, "decode %s", filepath.Join(root, t, name))
				}

				pkgs := map[string]scanTypes.OSPackage{}
				for _, p := range old.SrcPackages {
					for _, bn := range p.BinaryNames {
						pkgs[bn] = scanTypes.OSPackage{
							SrcName:    p.Name,
							SrcVersion: p.Version,
						}
					}
				}
				for _, p := range old.Packages {
					base := pkgs[p.Name]
					base.Name = p.Name
					base.Version = p.Version
					base.Release = p.Release
					base.NewVersion = p.NewVersion
					base.NewRelease = p.NewRelease
					base.Arch = p.Arch
					base.Repository = p.Repository
					base.ModularityLabel = p.ModularityLabel
					pkgs[p.Name] = base
				}

				new := scanTypes.ScanResult{
					JSONVersion: 0,
					ServerUUID:  id.String(),
					ServerName:  old.ServerName,
					Family:      old.Family,
					Release:     old.Release,

					Kernel: scanTypes.Kernel{
						Release:        old.RunningKernel.Release,
						Version:        old.RunningKernel.Version,
						RebootRequired: old.RunningKernel.RebootRequired,
					},
					OSPackages: func() []scanTypes.OSPackage {
						ps := make([]scanTypes.OSPackage, 0, len(pkgs))
						for _, p := range pkgs {
							ps = append(ps, p)
						}
						return ps
					}(),
					CPE: func() []string {
						s, ok := old.Config.Scan.Servers[old.ServerName]
						if !ok {
							return nil
						}
						return s.CpeNames
					}(),

					ScannedAt: time.Now(),
					ScannedBy: version.String(),
				}

				if err := os.MkdirAll(filepath.Join(options.resultsDir, id.String(), t), 0755); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.resultsDir, id.String(), t))
				}

				f, err = os.Create(filepath.Join(options.resultsDir, id.String(), t, "scan.json"))
				if err != nil {
					return errors.Wrapf(err, "create %s", filepath.Join(options.resultsDir, id.String(), t, "scan.json"))
				}
				defer f.Close()

				e := json.NewEncoder(f)
				e.SetEscapeHTML(false)
				e.SetIndent("", "  ")
				if err := e.Encode(new); err != nil {
					return errors.Wrapf(err, "encode %s", filepath.Join(options.resultsDir, id.String(), t, "scan.json"))
				}

				return nil
			}(); err != nil {
				return errors.WithStack(err)
			}
		}
	}

	return nil
}
