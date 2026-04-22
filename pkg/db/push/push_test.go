package push_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/klauspost/compress/zstd"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls2/pkg/db/push"
)

func TestPush(t *testing.T) {
	// Distinct payload bodies → distinct layer digests, so the
	// "already exists" / "force overwrite" cases are meaningful.
	existingBytes, err := compressZstd("existing-db")
	if err != nil {
		t.Fatalf("compressZstd(existing-db): %v", err)
	}
	newBytes, err := compressZstd("new-db")
	if err != nil {
		t.Fatalf("compressZstd(new-db): %v", err)
	}
	nonZstdBytes := []byte("plain text, no magic")

	type args struct {
		dbBytes []byte
		dbName  string
		tag     string
		digest  string
		token   string
		opts    []push.Option
	}

	tests := []struct {
		name    string
		args    args
		want    *ocispec.Manifest
		wantTag string // tag expected to resolve after the call; "" = no tag expected
		wantErr bool
	}{
		{
			name: "happy (tagged)",
			args: args{
				dbBytes: newBytes,
				dbName:  "vuls.db.zst",
				tag:     "v1",
				token:   "gho_xxx",
			},
			want: &ocispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: 2},
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.vulsio.vuls.db+type",
				Config:       ocispec.DescriptorEmptyJSON,
				Layers: []ocispec.Descriptor{{
					MediaType:   "application/vnd.vulsio.vuls.db.layer.v1+zstd",
					Digest:      godigest.Digest(fmt.Sprintf("sha256:%x", sha256.Sum256(newBytes))),
					Size:        int64(len(newBytes)),
					Annotations: map[string]string{ocispec.AnnotationTitle: "vuls.db.zst"},
				}},
			},
			wantTag: "v1",
		},
		{
			name: "tagless push",
			args: args{
				dbBytes: newBytes,
				dbName:  "vuls.db.zst",
				token:   "gho_xxx",
			},
			want: &ocispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: 2},
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.vulsio.vuls.db+type",
				Config:       ocispec.DescriptorEmptyJSON,
				Layers: []ocispec.Descriptor{{
					MediaType:   "application/vnd.vulsio.vuls.db.layer.v1+zstd",
					Digest:      godigest.Digest(fmt.Sprintf("sha256:%x", sha256.Sum256(newBytes))),
					Size:        int64(len(newBytes)),
					Annotations: map[string]string{ocispec.AnnotationTitle: "vuls.db.zst"},
				}},
			},
		},
		{
			name: "tag already exists",
			args: args{
				dbBytes: newBytes,
				dbName:  "vuls.db.zst",
				tag:     "existing",
				token:   "gho_xxx",
			},
			wantErr: true,
		},
		{
			name: "tag already exists, but force push",
			args: args{
				dbBytes: newBytes,
				dbName:  "vuls.db.zst",
				tag:     "existing",
				token:   "gho_xxx",
				opts:    []push.Option{push.WithForce(true)},
			},
			want: &ocispec.Manifest{
				Versioned:    specs.Versioned{SchemaVersion: 2},
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.vulsio.vuls.db+type",
				Config:       ocispec.DescriptorEmptyJSON,
				Layers: []ocispec.Descriptor{{
					MediaType:   "application/vnd.vulsio.vuls.db.layer.v1+zstd",
					Digest:      godigest.Digest(fmt.Sprintf("sha256:%x", sha256.Sum256(newBytes))),
					Size:        int64(len(newBytes)),
					Annotations: map[string]string{ocispec.AnnotationTitle: "vuls.db.zst"},
				}},
			},
			wantTag: "existing",
		},
		{
			name: "not zstd-compressed",
			args: args{
				dbBytes: nonZstdBytes,
				dbName:  "vuls.db.zst",
				tag:     "v1",
				token:   "gho_xxx",
			},
			wantErr: true,
		},
		{
			// Digest references must be rejected up front: they
			// would otherwise reach repo.Tag(..., <digest>) and
			// fail with a confusing registry error.
			name: "digest reference rejected",
			args: args{
				dbBytes: newBytes,
				dbName:  "vuls.db.zst",
				digest:  "sha256:33e976b83329e6acb35f96b2d6531080bdaf5eeb399d0a2c701098ee82a7f4e3",
				token:   "gho_xxx",
			},
			wantErr: true,
		},
		{
			name: "tag and digest reference rejected",
			args: args{
				dbBytes: newBytes,
				dbName:  "vuls.db.zst",
				tag:     "v1",
				digest:  "sha256:33e976b83329e6acb35f96b2d6531080bdaf5eeb399d0a2c701098ee82a7f4e3",
				token:   "gho_xxx",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(registry.New())
			defer ts.Close()

			originalTransport := http.DefaultTransport
			http.DefaultTransport = ts.Client().Transport
			defer func() {
				http.DefaultTransport = originalTransport
			}()

			u, err := url.Parse(ts.URL)
			if err != nil {
				t.Fatalf("parse url: %v", err)
			}

			repository := fmt.Sprintf("%s/vulsio/vuls-nightly-db", u.Host)

			if err := setupExisting(repository, "existing", existingBytes); err != nil {
				t.Fatalf("setup(): %v", err)
			}

			image := repository
			if tt.args.tag != "" {
				image = fmt.Sprintf("%s:%s", image, tt.args.tag)
			}
			if tt.args.digest != "" {
				image = fmt.Sprintf("%s@%s", image, tt.args.digest)
			}
			dbpath := filepath.Join(t.TempDir(), tt.args.dbName)
			if err := os.WriteFile(dbpath, tt.args.dbBytes, 0o600); err != nil {
				t.Fatalf("write fixture %q: %v", dbpath, err)
			}

			// Always capture the stdout-style digest output so the
			// table can assert both success (single sha256 line) and
			// failure (no output) paths.
			var digestOut bytes.Buffer
			opts := append([]push.Option{push.WithDigestWriter(&digestOut)}, tt.args.opts...)

			if err := push.Push(image, dbpath, tt.args.token, opts...); (err != nil) != tt.wantErr {
				t.Errorf("Push() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				if got := digestOut.String(); got != "" {
					t.Errorf("digest writer: want empty on error, got %q", got)
				}
				return
			}

			if tt.want == nil {
				t.Fatalf("want must be set for success case")
			}
			want := *tt.want

			manifestDigest := strings.TrimRight(digestOut.String(), "\n")
			if !strings.HasPrefix(manifestDigest, "sha256:") || strings.Contains(manifestDigest, "\n") {
				t.Errorf("digest writer: want single %q line, got %q", "sha256:<hex>", digestOut.String())
			}
			if err := checkManifest(repository, manifestDigest, want); err != nil {
				t.Errorf("checkManifest() by digest: %v", err)
			}
			if err := checkBlobExists(repository, want.Layers[0].Digest); err != nil {
				t.Errorf("checkBlobExists(): %v", err)
			}

			if tt.wantTag != "" {
				if err := checkManifest(repository, tt.wantTag, want); err != nil {
					t.Errorf("checkManifest() by tag: %v", err)
				}
			} else {
				// Tagless push: `newTag` must not have been created.
				if err := checkNoTag(repository, "v1"); err != nil {
					t.Errorf("checkNoTag(): %v", err)
				}
			}
		})
	}
}

func compressZstd(payload string) ([]byte, error) {
	var b bytes.Buffer

	zw, err := zstd.NewWriter(&b)
	if err != nil {
		return nil, errors.Wrap(err, "create zstd writer")
	}
	if _, err := zw.Write([]byte(payload)); err != nil {
		return nil, errors.Wrap(err, "write zstd payload")
	}
	if err := zw.Close(); err != nil {
		return nil, errors.Wrap(err, "close zstd writer")
	}

	return b.Bytes(), nil
}

func setupExisting(repository, tag string, bs []byte) error {
	ctx := context.TODO()

	repo, err := remote.NewRepository(repository)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", repository)
	}
	if repo.Reference.Reference != "" {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>"}, repository)
	}

	layerDescriptor, err := oras.PushBytes(ctx, repo, "application/vnd.vulsio.vuls.db.layer.v1+zstd", bs)
	if err != nil {
		return errors.Wrap(err, "push vuls db layer")
	}
	if layerDescriptor.Annotations == nil {
		layerDescriptor.Annotations = make(map[string]string)
	}
	if _, ok := layerDescriptor.Annotations[ocispec.AnnotationTitle]; !ok {
		layerDescriptor.Annotations[ocispec.AnnotationTitle] = "vuls.db.zst"
	}

	desc, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, "application/vnd.vulsio.vuls.db+type", oras.PackManifestOptions{Layers: []ocispec.Descriptor{layerDescriptor}})
	if err != nil {
		return errors.Wrap(err, "pack manifest")
	}

	if err := repo.Tag(ctx, desc, tag); err != nil {
		return errors.Wrapf(err, "tagged for %+v", desc)
	}

	return nil
}

func checkManifest(repository, reference string, want ocispec.Manifest) error {
	repo, err := remote.NewRepository(repository)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", repository)
	}
	if repo.Reference.Reference != "" {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>"}, repository)
	}

	_, fetchedManifestContent, err := oras.FetchBytes(context.TODO(), repo, reference, oras.DefaultFetchBytesOptions)
	if err != nil {
		return errors.Wrapf(err, "fetch manifest for %s", reference)
	}

	var got ocispec.Manifest
	if err := json.Unmarshal(fetchedManifestContent, &got); err != nil {
		return errors.Wrap(err, "unmarshal manifest")
	}

	if got.Annotations != nil {
		delete(got.Annotations, "org.opencontainers.image.created")
		if len(got.Annotations) == 0 {
			got.Annotations = nil
		}
	}
	if want.Annotations != nil {
		delete(want.Annotations, "org.opencontainers.image.created")
		if len(want.Annotations) == 0 {
			want.Annotations = nil
		}
	}

	if diff := cmp.Diff(got, want); diff != "" {
		return errors.Errorf("manifest mismatch (-got +want):\n%s", diff)
	}

	return nil
}

func checkBlobExists(repository string, dgst godigest.Digest) error {
	repo, err := remote.NewRepository(repository)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", repository)
	}
	if _, err := repo.Blobs().Resolve(context.TODO(), string(dgst)); err != nil {
		return errors.Wrapf(err, "resolve blob %q", dgst)
	}
	return nil
}

func checkNoTag(repository, tag string) error {
	repo, err := remote.NewRepository(repository)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", repository)
	}
	if _, err := repo.Resolve(context.TODO(), tag); err == nil {
		return errors.Errorf("tag %q unexpectedly exists in %q", tag, repository)
	} else if !errors.Is(err, errdef.ErrNotFound) {
		return errors.Wrapf(err, "resolve tag %q", tag)
	}
	return nil
}
