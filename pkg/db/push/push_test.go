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
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	containerregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/klauspost/compress/zstd"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry"
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
		image   string
		dbBytes []byte
		dbName  string
		token   string
		opts    []push.Option
	}

	tests := []struct {
		name    string
		args    args
		want    ocispec.Manifest
		wantTag string // tag expected to resolve after the call; "" = no tag expected
		wantErr bool
	}{
		{
			name: "happy (tagged)",
			args: args{
				image:   "ghcr.io/vulsio/vuls-nightly-db:v1",
				dbBytes: newBytes,
				dbName:  "vuls.db.zst",
				token:   "gho_xxx",
			},
			want: ocispec.Manifest{
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
				Annotations: map[string]string{
					"org.opencontainers.image.created": time.Now().UTC().Format(time.RFC3339),
				},
			},
			wantTag: "v1",
		},
		{
			name: "tagless push",
			args: args{
				image:   "ghcr.io/vulsio/vuls-nightly-db",
				dbBytes: newBytes,
				dbName:  "vuls.db.zst",
				token:   "gho_xxx",
			},
			want: ocispec.Manifest{
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
				Annotations: map[string]string{
					"org.opencontainers.image.created": time.Now().UTC().Format(time.RFC3339),
				},
			},
		},
		{
			name: "tag already exists",
			args: args{
				image:   "ghcr.io/vulsio/vuls-nightly-db:existing",
				dbBytes: newBytes,
				dbName:  "vuls.db.zst",
				token:   "gho_xxx",
			},
			wantErr: true,
		},
		{
			name: "tag already exists, but force push",
			args: args{
				image:   "ghcr.io/vulsio/vuls-nightly-db:existing",
				dbBytes: newBytes,
				dbName:  "vuls.db.zst",
				token:   "gho_xxx",
				opts:    []push.Option{push.WithForce(true)},
			},
			want: ocispec.Manifest{
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
				Annotations: map[string]string{
					"org.opencontainers.image.created": time.Now().UTC().Format(time.RFC3339),
				},
			},
			wantTag: "existing",
		},
		{
			name: "not zstd-compressed",
			args: args{
				image:   "ghcr.io/vulsio/vuls-nightly-db:v1",
				dbBytes: nonZstdBytes,
				dbName:  "vuls.db.zst",
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
				image:   "ghcr.io/vulsio/vuls-nightly-db@sha256:33e976b83329e6acb35f96b2d6531080bdaf5eeb399d0a2c701098ee82a7f4e3",
				dbBytes: newBytes,
				dbName:  "vuls.db.zst",
				token:   "gho_xxx",
			},
			wantErr: true,
		},
		{
			name: "tag and digest reference rejected",
			args: args{
				image:   "ghcr.io/vulsio/vuls-nightly-db:v1@sha256:33e976b83329e6acb35f96b2d6531080bdaf5eeb399d0a2c701098ee82a7f4e3",
				dbBytes: newBytes,
				dbName:  "vuls.db.zst",
				token:   "gho_xxx",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(containerregistry.New())
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

			ref, err := remote.NewRepository(tt.args.image)
			if err != nil {
				t.Fatalf("parse repository %q: %v", tt.args.image, err)
			}
			ref.Reference.Registry = u.Host

			repo := &remote.Repository{
				Reference: registry.Reference{
					Registry:   ref.Reference.Registry,
					Repository: ref.Reference.Repository,
				},
			}

			if err := setupExisting(repo, "existing", existingBytes); err != nil {
				t.Fatalf("setup(): %v", err)
			}

			dbpath := filepath.Join(t.TempDir(), tt.args.dbName)
			if err := os.WriteFile(dbpath, tt.args.dbBytes, 0o600); err != nil {
				t.Fatalf("write fixture %q: %v", dbpath, err)
			}

			var digestOut bytes.Buffer
			tt.args.opts = append(tt.args.opts, push.WithDigestWriter(&digestOut))

			if err := push.Push(ref.Reference.String(), dbpath, tt.args.token, tt.args.opts...); (err != nil) != tt.wantErr {
				t.Errorf("Push() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			rawDigest := digestOut.String()
			if !strings.HasSuffix(rawDigest, "\n") || strings.Count(rawDigest, "\n") != 1 {
				t.Errorf("digest writer: want single %q line, got %q", "sha256:<hex>", rawDigest)
				return
			}
			manifestDigest := strings.TrimSuffix(rawDigest, "\n")
			if !strings.HasPrefix(manifestDigest, "sha256:") || strings.Contains(manifestDigest, "\n") {
				t.Errorf("digest writer: want single %q line, got %q", "sha256:<hex>", rawDigest)
			}
			if err := checkManifest(repo, manifestDigest, tt.want); err != nil {
				t.Errorf("checkManifest() by digest: %v", err)
			}
			if err := checkBlobExists(repo, tt.want.Layers[0].Digest); err != nil {
				t.Errorf("checkBlobExists(): %v", err)
			}

			if tt.wantTag != "" {
				if err := checkManifest(repo, tt.wantTag, tt.want); err != nil {
					t.Errorf("checkManifest() by tag: %v", err)
				}
			} else {
				// Tagless push must not create any new tag; only the
				// pre-seeded "existing" tag should remain.
				if err := checkTags(repo, []string{"existing"}); err != nil {
					t.Errorf("checkTags(): %v", err)
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

func setupExisting(repo *remote.Repository, tag string, bs []byte) error {
	ctx := context.TODO()

	if repo.Reference.Reference != "" {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>"}, fmt.Sprintf("%s/%s:%s", repo.Reference.Host(), repo.Reference.Repository, repo.Reference.Reference))
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

func checkManifest(repo *remote.Repository, reference string, want ocispec.Manifest) error {
	if repo.Reference.Reference != "" {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>"}, fmt.Sprintf("%s/%s:%s", repo.Reference.Host(), repo.Reference.Repository, repo.Reference.Reference))
	}

	_, fetchedManifestContent, err := oras.FetchBytes(context.TODO(), repo, reference, oras.DefaultFetchBytesOptions)
	if err != nil {
		return errors.Wrapf(err, "fetch manifest for %s", reference)
	}

	var got ocispec.Manifest
	if err := json.Unmarshal(fetchedManifestContent, &got); err != nil {
		return errors.Wrap(err, "unmarshal manifest")
	}

	if diff := cmp.Diff(got, want, cmpopts.IgnoreMapEntries(func(k, v string) bool {
		return k == "org.opencontainers.image.created"
	})); diff != "" {
		return errors.Errorf("manifest mismatch (-got +want):\n%s", diff)
	}

	return nil
}

func checkBlobExists(repo *remote.Repository, dgst godigest.Digest) error {
	if _, err := repo.Blobs().Resolve(context.TODO(), string(dgst)); err != nil {
		return errors.Wrapf(err, "resolve blob %q", dgst)
	}
	return nil
}

func checkTags(repo *remote.Repository, want []string) error {
	var tags []string
	if err := repo.Tags(context.TODO(), "", func(ts []string) error {
		tags = append(tags, ts...)
		return nil
	}); err != nil {
		return errors.Wrap(err, "list tags")
	}

	if diff := cmp.Diff(tags, want, cmpopts.SortSlices(func(x, y string) bool { return x < y })); diff != "" {
		return errors.Errorf("tag list mismatch (-got +want):\n%s", diff)
	}

	return nil
}
