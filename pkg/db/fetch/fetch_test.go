package fetch_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	containerregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls2/pkg/db/fetch"
	dbinit "github.com/MaineK00n/vuls2/pkg/db/init"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
	}{
		{
			name: "with manifest annotations",
			annotations: map[string]string{
				"org.opencontainers.image.created":  "2026-07-22T20:48:17Z",
				"org.opencontainers.image.revision": "0123abc",
				"io.vuls.db.branch":                 "nightly",
			},
		},
		{
			name:        "without manifest annotations",
			annotations: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			srcpath := filepath.Join(dir, "src.db")
			if err := dbinit.Init(dbinit.WithDBType("boltdb"), dbinit.WithDBPath(srcpath)); err != nil {
				t.Fatalf("init db: %v", err)
			}

			bs, err := os.ReadFile(srcpath)
			if err != nil {
				t.Fatalf("read src db: %v", err)
			}

			var zbs bytes.Buffer
			zw, err := zstd.NewWriter(&zbs)
			if err != nil {
				t.Fatalf("new zstd writer: %v", err)
			}
			if _, err := zw.Write(bs); err != nil {
				t.Fatalf("write zstd payload: %v", err)
			}
			if err := zw.Close(); err != nil {
				t.Fatalf("close zstd writer: %v", err)
			}

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

			repo := &remote.Repository{
				Reference: registry.Reference{
					Registry:   u.Host,
					Repository: "vulsio/vuls-nightly-db",
				},
			}

			ctx := context.TODO()

			layerDescriptor, err := oras.PushBytes(ctx, repo, "application/vnd.vulsio.vuls.db.layer.v1+zstd", zbs.Bytes())
			if err != nil {
				t.Fatalf("push layer: %v", err)
			}
			if layerDescriptor.Annotations == nil {
				layerDescriptor.Annotations = make(map[string]string)
			}
			layerDescriptor.Annotations[ocispec.AnnotationTitle] = "vuls.db.zst"

			desc, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, "application/vnd.vulsio.vuls.db+type", oras.PackManifestOptions{
				Layers:              []ocispec.Descriptor{layerDescriptor},
				ManifestAnnotations: tt.annotations,
			})
			if err != nil {
				t.Fatalf("pack manifest: %v", err)
			}
			if err := repo.Tag(ctx, desc, "nightly"); err != nil {
				t.Fatalf("tag manifest: %v", err)
			}

			dbpath := filepath.Join(dir, "vuls.db")
			if err := fetch.Fetch(
				fetch.WithRepository(fmt.Sprintf("%s/vulsio/vuls-nightly-db:nightly", u.Host)),
				fetch.WithDBPath(dbpath),
				fetch.WithNoProgress(true),
			); err != nil {
				t.Fatalf("Fetch() error = %v", err)
			}

			meta, err := readMetadata(dbpath)
			if err != nil {
				t.Fatalf("read metadata: %v", err)
			}

			if meta.Digest == nil || *meta.Digest != desc.Digest.String() {
				t.Errorf("metadata digest: want %q, got %v", desc.Digest.String(), meta.Digest)
			}
			if meta.Downloaded == nil {
				t.Errorf("metadata downloaded: want non-nil, got nil")
			}
			// PackManifest auto-adds org.opencontainers.image.created when
			// no annotations are given, so the copied map is never empty.
			want := tt.annotations
			if want == nil {
				got, ok := meta.Annotations["org.opencontainers.image.created"]
				if !ok || got == "" {
					t.Errorf("metadata annotations: want auto-generated %q, got %+v", "org.opencontainers.image.created", meta.Annotations)
				}
				return
			}
			if diff := cmp.Diff(meta.Annotations, want); diff != "" {
				t.Errorf("metadata annotations mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func readMetadata(dbpath string) (*dbTypes.Metadata, error) {
	s, err := (&session.Config{
		Type:    "boltdb",
		Path:    dbpath,
		Options: session.StorageOptions{BoltDB: bolt.DefaultOptions},
	}).New()
	if err != nil {
		return nil, err
	}
	if err := s.Storage().Open(); err != nil {
		return nil, err
	}
	defer s.Storage().Close()

	return s.Storage().GetMetadata()
}
