package build_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls2/pkg/db/build"
)

func TestReadLock(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"

	tests := []struct {
		name    string
		in      string
		want    build.Lock
		wantErr bool
	}{
		{
			name: "valid",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"},
					{"name": "redhat-vex-v1-rhel", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-redhat-vex-v1-rhel", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			want: build.Lock{
				Branch: "nightly",
				Sources: []build.Source{
					{Name: "alma-errata", Repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", Commit: commit},
					{Name: "redhat-vex-v1-rhel", Repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-redhat-vex-v1-rhel", Commit: commit},
				},
			},
		},
		{
			name: "sources from different registries and tags",
			in: `{
				"branch": "main",
				"sources": [
					{"name": "alma-errata", "repository": "127.0.0.1:5000/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"},
					{"name": "test", "repository": "ghcr.io/example/fork:test-tag", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			want: build.Lock{
				Branch: "main",
				Sources: []build.Source{
					{Name: "alma-errata", Repository: "127.0.0.1:5000/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", Commit: commit},
					{Name: "test", Repository: "ghcr.io/example/fork:test-tag", Commit: commit},
				},
			},
		},
		{
			name: "branch with slash",
			in: `{
				"branch": "release/v1",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			want: build.Lock{
				Branch:  "release/v1",
				Sources: []build.Source{{Name: "alma-errata", Repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", Commit: commit}},
			},
		},
		{
			name: "branch with revision suffix ~1",
			in: `{
				"branch": "nightly~1",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch with revision suffix ^{commit}",
			in: `{
				"branch": "nightly^{commit}",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch with range",
			in: `{
				"branch": "main..nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch with reflog",
			in: `{
				"branch": "nightly@{1}",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch starting with dash",
			in: `{
				"branch": "-nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch with space",
			in: `{
				"branch": "night ly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch ending in .lock",
			in: `{
				"branch": "nightly.lock",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch HEAD",
			in: `{
				"branch": "HEAD",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch @",
			in: `{
				"branch": "@",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "missing branch",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "unknown member",
			in: `{
				"branch": "nightly",
				"registry": "ghcr.io/vulsio/vuls-data-db",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "unknown source member",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567", "approved": {}}
				]
			}`,
			wantErr: true,
		},
		{
			name: "no sources",
			in: `{
				"branch": "nightly",
				"sources": [

				]
			}`,
			wantErr: true,
		},
		{
			name: "empty name",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "duplicate name",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"},
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata-2", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "missing repository",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository without tag",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository with digest",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository host ..",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "../vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository host .",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "./vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository without host",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository host only",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository with uppercase path",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/Vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository with empty path component",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio//vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository with invalid tag",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:alpha[", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "tag too long",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "duplicate repository",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"},
					{"name": "alma-errata-2", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "short commit",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "uppercase commit",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789ABCDEF0123456789ABCDEF01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch name as commit",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "nightly"}
				]
			}`,
			wantErr: true,
		},
		{
			name:    "not json",
			in:      `branch: nightly`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := build.ReadLock(strings.NewReader(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ReadLock() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ReadLock() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
