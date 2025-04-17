package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	progressbar "github.com/schollz/progressbar/v3"
	bolt "go.etcd.io/bbolt"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"

	db "github.com/MaineK00n/vuls2/pkg/db/common"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

type options struct {
	dbpath string
	dbopts db.DBOptions

	repository string
	noProgress bool
	debug      bool
}

type Option interface {
	apply(*options)
}

type dbpathOption string

func (o dbpathOption) apply(opts *options) {
	opts.dbpath = string(o)
}

func WithDBPath(dbpath string) Option {
	return dbpathOption(dbpath)
}

type dboptsOption db.DBOptions

func (o dboptsOption) apply(opts *options) {
	opts.dbopts = db.DBOptions(o)
}

func WithDBOptions(dbopts db.DBOptions) Option {
	return dboptsOption(dbopts)
}

type repositoryOption string

func (o repositoryOption) apply(opts *options) {
	opts.repository = string(o)
}

func WithRepository(repository string) Option {
	return repositoryOption(repository)
}

type debugOption bool

func (o debugOption) apply(opts *options) {
	opts.debug = bool(o)
}

func WithDebug(debug bool) Option {
	return debugOption(debug)
}

type noProgressOption bool

func (o noProgressOption) apply(opts *options) {
	opts.noProgress = bool(o)
}

func WithNoProgress(noProgress bool) Option {
	return noProgressOption(noProgress)
}

func Fetch(opts ...Option) error {
	options := &options{
		dbpath:     filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		dbopts:     db.DBOptions{BoltDB: bolt.DefaultOptions},
		repository: "ghcr.io/mainek00n/vuls2:latest",
		debug:      false,
		noProgress: false,
	}
	for _, o := range opts {
		o.apply(options)
	}

	slog.Info("Fetch vuls.db", "repository", options.repository)

	ctx := context.TODO()

	ms := memory.New()

	repo, err := remote.NewRepository(options.repository)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", options.repository)
	}
	if repo.Reference.Reference == "" {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>@<digest>", "<repository>:<tag>", "<repository>:<tag>@<digest>"}, options.repository)
	}

	manifestDescriptor, err := oras.Copy(ctx, repo, repo.Reference.Reference, ms, repo.Reference.Reference, oras.DefaultCopyOptions)
	if err != nil {
		return errors.Wrapf(err, "copy from %s", options.repository)
	}

	r, err := ms.Fetch(ctx, manifestDescriptor)
	if err != nil {
		return errors.Wrap(err, "fetch manifest")
	}
	defer r.Close() //nolint:errcheck

	var manifest ocispec.Manifest
	if err := json.NewDecoder(content.NewVerifyReader(r, manifestDescriptor)).Decode(&manifest); err != nil {
		return errors.Wrap(err, "decode manifest")
	}

	l := func() *ocispec.Descriptor {
		for _, l := range manifest.Layers {
			if l.MediaType == "application/vnd.vulsio.vuls.db.layer.v1+zstd" {
				return &l
			}
		}
		return nil
	}()
	if l == nil {
		return errors.Errorf("not found digest and filename from layers, actual layers: %#v", manifest.Layers)
	}

	r, err = repo.Fetch(ctx, *l)
	if err != nil {
		return errors.Wrap(err, "fetch content")
	}
	defer r.Close() //nolint:errcheck

	d, err := zstd.NewReader(content.NewVerifyReader(r, *l))
	if err != nil {
		return errors.Wrap(err, "new zstd reader")
	}
	defer d.Close() //nolint:errcheck

	if err := os.MkdirAll(filepath.Dir(options.dbpath), 0755); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(options.dbpath))
	}

	if err := options.write(d); err != nil {
		return errors.Wrapf(err, "write to %s", options.dbpath)
	}

	dbc, err := (&db.Config{
		Type:    "boltdb",
		Path:    options.dbpath,
		Debug:   options.debug,
		Options: options.dbopts,
	}).New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}
	if err := dbc.Open(); err != nil {
		return errors.Wrap(err, "db open")
	}
	defer dbc.Close() //nolint:errcheck

	meta, err := dbc.GetMetadata()
	if err != nil || meta == nil {
		return errors.Wrap(err, "get metadata")
	}
	if meta.SchemaVersion != db.SchemaVersion {
		return errors.Errorf("unexpected schema version. expected: %d, actual: %d", db.SchemaVersion, meta.SchemaVersion)
	}

	meta.Downloaded = func() *time.Time {
		t := time.Now()
		return &t
	}()
	if err := dbc.PutMetadata(*meta); err != nil {
		return errors.Wrap(err, "put metadata")
	}

	return nil
}

func (o *options) write(d *zstd.Decoder) error {
	tmpPath := fmt.Sprintf("%s.tmp", o.dbpath)
	f, err := os.Create(tmpPath)
	if err != nil {
		return errors.Wrapf(err, "create %s", tmpPath)
	}
	defer func() {
		_ = f.Close() //nolint:errcheck
		_ = os.Remove(tmpPath)
	}()

	pb := func() *progressbar.ProgressBar {
		if o.noProgress {
			return progressbar.DefaultBytesSilent(-1)
		}
		return progressbar.DefaultBytes(-1, "fetching")
	}()
	defer pb.Close() //nolint:errcheck

	if _, err := d.WriteTo(io.MultiWriter(f, pb)); err != nil {
		return errors.Wrapf(err, "write to %s", tmpPath)
	}

	if err := os.Rename(tmpPath, o.dbpath); err != nil {
		return errors.Wrapf(err, "rename %s to %s", tmpPath, o.dbpath)
	}

	return nil
}
