package scan

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
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
				if err := json.UnmarshalRead(f, &old); err != nil {
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
					// Repository is where the INSTALLED build came from, which
					// is what a repository-gated criterion matches against.
					// Carry it only for the ecosystems whose data actually
					// gates on it: redhat (centos resolves to the redhat
					// ecosystem too), amazon and alpine.
					//
					// Everywhere else the value is at best unused and at worst
					// wrong. vuls overwrites it with the CANDIDATE version's
					// repository whenever an update is pending
					// (models.Packages.MergeNewVersion), and for the Debian
					// family that is an apt suite -- noble-updates/main -- which
					// can never equal a repository an Ubuntu data source
					// claims. Gating on it would drop the criteria for exactly
					// the packages whose fix is already published, silently.
					//
					// An allowlist rather than a denylist so that a family
					// added later, or a scanner that starts reporting something
					// new, defaults to not gating: that only ever loses
					// filtering, never a detection.
					switch old.Family {
					case ecosystemTypes.EcosystemTypeRedHat, ecosystemTypes.EcosystemTypeCentOS,
						ecosystemTypes.EcosystemTypeAmazon, ecosystemTypes.EcosystemTypeAlpine:
						base.Repository = p.Repository
					}
					// ModularityLabel names an RPM module stream. It is not
					// matched on its own: base.formQuery() folds it into the
					// package name -- mysql:8.0::community-mysql -- and only
					// the ecosystems whose data emits that form can match it:
					// redhat (centos resolves to the redhat ecosystem too),
					// alma, rocky, oracle and fedora.
					//
					// The fold runs for the binary name of EVERY family, so a
					// value that leaks in elsewhere rewrites the name into
					// something no criterion carries, and one that is not
					// NAME:STREAM(:VERSION:CONTEXT:ARCH) shaped fails the whole
					// query with an error.
					//
					// An allowlist for the same reason as Repository above.
					switch old.Family {
					case ecosystemTypes.EcosystemTypeRedHat, ecosystemTypes.EcosystemTypeCentOS,
						ecosystemTypes.EcosystemTypeAlma, ecosystemTypes.EcosystemTypeRocky,
						ecosystemTypes.EcosystemTypeOracle, ecosystemTypes.EcosystemTypeFedora:
						base.ModularityLabel = p.ModularityLabel
					}
					pkgs[p.Name] = base
				}

				new := scanTypes.ScanResult{
					JSONVersion: 0,
					ServerUUID:  id.String(),
					ServerName:  old.ServerName,
					Family:      ecosystemTypes.Ecosystem(old.Family),
					Release:     old.Release,

					Kernel: scanTypes.Kernel{
						Release:        old.RunningKernel.Release,
						Version:        old.RunningKernel.Version,
						RebootRequired: old.RunningKernel.RebootRequired,
					},
					OSPackages: func() []scanTypes.OSPackage {
						ps := make([]scanTypes.OSPackage, 0, len(pkgs)+1)
						for _, p := range pkgs {
							ps = append(ps, p)
						}
						// For Windows, include the OS release as a synthetic package so that
						// kernel-version-based detection can report the correct release name.
						if old.Family == "windows" && old.RunningKernel.Version != "" && old.Release != "" {
							ps = append(ps, scanTypes.OSPackage{
								Name:    old.Release,
								Version: old.RunningKernel.Version,
							})
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

				if err := json.MarshalWrite(f, new, jsontext.WithIndent("  ")); err != nil {
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
