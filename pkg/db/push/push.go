package push

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

type options struct {
	force        bool
	digestWriter io.Writer
}

type Option interface {
	apply(*options)
}

type forceOption bool

func (f forceOption) apply(opts *options) {
	opts.force = bool(f)
}

func WithForce(force bool) Option {
	return forceOption(force)
}

type digestWriterOption struct{ w io.Writer }

func (o digestWriterOption) apply(opts *options) {
	opts.digestWriter = o.w
}

// WithDigestWriter overrides the io.Writer that Push writes the pushed
// manifest's digest (e.g. `sha256:abcd...`) to, followed by a newline.
// Defaults to os.Stdout so CLI callers can capture it with
// `digest=$(vuls db push ...)`. The write happens AFTER the manifest is
// persisted in the registry and BEFORE the optional tag step, so the
// digest is reported even when the subsequent tagging step fails.
func WithDigestWriter(w io.Writer) Option {
	return digestWriterOption{w: w}
}

// Push uploads the vuls db to the given registry reference.
//
// The reference may be either `<repository>:<tag>` or bare `<repository>`.
// When a tag is omitted the manifest is pushed but no tag is attached, so
// the image is reachable only by digest. The pushed manifest's digest is
// written (with a trailing newline) to os.Stdout by default; pass
// WithDigestWriter to redirect it.
//
// Digest references (`<repository>@<digest>`) are rejected: a push target
// must be addressable by tag (or bare repository for a digest-only push).
func Push(image, dbpath, token string, opts ...Option) error {
	options := &options{
		force:        false,
		digestWriter: os.Stdout,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	ctx := context.TODO()

	repo, err := remote.NewRepository(image)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", image)
	}

	// Digest references (`<repository>@<digest>`) are rejected: oras
	// accepts them in remote.NewRepository, but later we would try to
	// repo.Tag(..., <digest>) which is invalid and surfaces as a confusing
	// registry error. Callers that want a digest-only push should pass
	// the bare repository reference and read the digest off the
	// digestWriter (see WithDigestWriter).
	if _, err := repo.Reference.Digest(); err == nil {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>", "<repository>:<tag>"}, image)
	}

	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential(repo.Reference.Host(), auth.Credential{
			Username: "user", // Any string but empty
			Password: token,
		}),
	}

	// Existing-tag check only applies when a tag is specified. A tagless
	// push is always safe: manifests are content-addressable and pushing
	// an identical one is a no-op at the registry level.
	if repo.Reference.Reference != "" && !options.force {
		_, err := repo.Resolve(ctx, repo.Reference.Reference)
		if err != nil && !errors.Is(err, errdef.ErrNotFound) {
			return errors.Wrap(err, "check existing tag")
		}
		if err == nil {
			return errors.Errorf("tag %q already exists in %q", repo.Reference.Reference, repo.Reference.Repository)
		}
	}

	bs, err := os.ReadFile(dbpath)
	if err != nil {
		return errors.Wrapf(err, "read %q", dbpath)
	}

	zstdMagicNumber := []byte{0x28, 0xB5, 0x2F, 0xFD}
	if !bytes.HasPrefix(bs, zstdMagicNumber) {
		return errors.Errorf("%q is not Zstandard compressed file", dbpath)
	}

	layerDescriptor, err := oras.PushBytes(ctx, repo, "application/vnd.vulsio.vuls.db.layer.v1+zstd", bs)
	if err != nil {
		return errors.Wrap(err, "push vuls db layer")
	}
	if layerDescriptor.Annotations == nil {
		layerDescriptor.Annotations = make(map[string]string)
	}
	if _, ok := layerDescriptor.Annotations[ocispec.AnnotationTitle]; !ok {
		layerDescriptor.Annotations[ocispec.AnnotationTitle] = filepath.Base(dbpath)
	}

	desc, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, "application/vnd.vulsio.vuls.db+type", oras.PackManifestOptions{Layers: []ocispec.Descriptor{layerDescriptor}})
	if err != nil {
		return errors.Wrap(err, "pack manifest")
	}

	// Emit the resulting digest BEFORE attempting to tag: the manifest
	// is already persisted in the registry at this point, so writing the
	// digest early means callers can still recover the pushed image (by
	// digest) even when the subsequent tagging step fails.
	if _, err := fmt.Fprintln(options.digestWriter, desc.Digest.String()); err != nil {
		return errors.Wrap(err, "write digest")
	}

	if repo.Reference.Reference != "" {
		if err := repo.Tag(ctx, desc, repo.Reference.Reference); err != nil {
			return errors.Wrapf(err, "tagged for %+v", desc)
		}
	}

	return nil
}
