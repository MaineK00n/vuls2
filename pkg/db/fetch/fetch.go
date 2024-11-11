package fetch

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	progressbar "github.com/schollz/progressbar/v3"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"

	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

type options struct {
	dbpath string

	debug bool
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

type debugOption bool

func (o debugOption) apply(opts *options) {
	opts.debug = bool(o)
}

func WithDebug(debug bool) Option {
	return debugOption(debug)
}

func Fetch(opts ...Option) error {
	options := &options{
		dbpath: filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		debug:  false,
	}
	for _, o := range opts {
		o.apply(options)
	}

	slog.Info("Fetch vuls.db from ghcr.io/mainek00n/vuls2")

	ctx := context.TODO()

	ms := memory.New()

	repo, err := remote.NewRepository("ghcr.io/mainek00n/vuls2")
	if err != nil {
		return errors.Wrap(err, "create client for ghcr.io/mainek00n/vuls2")
	}

	manifestDescriptor, err := oras.Copy(ctx, repo, "latest", ms, "latest", oras.DefaultCopyOptions)
	if err != nil {
		return errors.Wrap(err, "copy from ghcr.io/mainek00n/vuls2")
	}

	r, err := ms.Fetch(ctx, manifestDescriptor)
	if err != nil {
		return errors.Wrap(err, "fetch manifest")
	}
	defer r.Close()

	var manifest ocispec.Manifest
	if err := json.NewDecoder(content.NewVerifyReader(r, manifestDescriptor)).Decode(&manifest); err != nil {
		return errors.Wrap(err, "decode manifest")
	}

	l := func() *ocispec.Descriptor {
		for _, l := range manifest.Layers {
			if l.MediaType == "application/vnd.mainek00n.vuls.db.layer.v1+zstd" {
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
	defer r.Close()

	d, err := zstd.NewReader(content.NewVerifyReader(r, *l))
	if err != nil {
		return errors.Wrap(err, "new zstd reader")
	}
	defer d.Close()

	if err := os.MkdirAll(filepath.Dir(options.dbpath), 0755); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(options.dbpath))
	}

	f, err := os.Create(options.dbpath)
	if err != nil {
		return errors.Wrapf(err, "create %s", options.dbpath)
	}
	defer f.Close()

	if _, err := d.WriteTo(io.MultiWriter(f, progressbar.DefaultBytes(-1, "downloading"))); err != nil {
		return errors.Wrapf(err, "write to %s", options.dbpath)
	}

	return nil
}