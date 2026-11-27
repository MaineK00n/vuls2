package build_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls2/pkg/db/build"
)

func TestReadLock(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    build.Lock
		wantErr bool
	}{
		{
			name: "valid",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"},
					{"name": "redhat-vex-v1-rhel", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-redhat-vex-v1-rhel", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			want: build.Lock{
				Sources: []build.Source{
					{Name: "alma-errata", Repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", Branch: "nightly", Commit: "0123456789abcdef0123456789abcdef01234567"},
					{Name: "redhat-vex-v1-rhel", Repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-redhat-vex-v1-rhel", Branch: "nightly", Commit: "0123456789abcdef0123456789abcdef01234567"},
				},
			},
		},
		{
			name: "sources from different registries and tags",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "127.0.0.1:5000/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "main", "commit": "0123456789abcdef0123456789abcdef01234567"},
					{"name": "test", "repository": "ghcr.io/example/fork:test-tag", "branch": "main", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			want: build.Lock{
				Sources: []build.Source{
					{Name: "alma-errata", Repository: "127.0.0.1:5000/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", Branch: "main", Commit: "0123456789abcdef0123456789abcdef01234567"},
					{Name: "test", Repository: "ghcr.io/example/fork:test-tag", Branch: "main", Commit: "0123456789abcdef0123456789abcdef01234567"},
				},
			},
		},
		{
			name: "sources on different branches",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"},
					{"name": "redhat-vex-v1-rhel", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-redhat-vex-v1-rhel", "branch": "main", "commit": "89abcdef0123456789abcdef0123456789abcdef"}
				]
			}`,
			want: build.Lock{
				Sources: []build.Source{
					{Name: "alma-errata", Repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", Branch: "nightly", Commit: "0123456789abcdef0123456789abcdef01234567"},
					{Name: "redhat-vex-v1-rhel", Repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-redhat-vex-v1-rhel", Branch: "main", Commit: "89abcdef0123456789abcdef0123456789abcdef"},
				},
			},
		},
		{
			name: "source with hold",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567", "hold": true},
					{"name": "alma-osv", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-osv", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567", "hold": false},
					{"name": "redhat-vex-v1-rhel", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-redhat-vex-v1-rhel", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			want: build.Lock{
				Sources: []build.Source{
					{Name: "alma-errata", Repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", Branch: "nightly", Commit: "0123456789abcdef0123456789abcdef01234567", Hold: true},
					{Name: "alma-osv", Repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-osv", Branch: "nightly", Commit: "0123456789abcdef0123456789abcdef01234567"},
					{Name: "redhat-vex-v1-rhel", Repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-redhat-vex-v1-rhel", Branch: "nightly", Commit: "0123456789abcdef0123456789abcdef01234567"},
				},
			},
		},
		{
			name: "branch with slash",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "release/v1", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			want: build.Lock{
				Sources: []build.Source{{Name: "alma-errata", Repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", Branch: "release/v1", Commit: "0123456789abcdef0123456789abcdef01234567"}},
			},
		},
		{
			name: "branch with revision suffix ~1",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly~1", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch with revision suffix ^{commit}",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly^{commit}", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch with range",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "main..nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch with reflog",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly@{1}", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch starting with dash",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "-nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch with space",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "night ly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch ending in .lock",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly.lock", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch HEAD",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "HEAD", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch @",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "@", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "source without branch",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "empty branch",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			// Every source's branch is checked, not only the first one's.
			name: "invalid branch on a later source",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"},
					{"name": "redhat-vex-v1-rhel", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-redhat-vex-v1-rhel", "branch": "nightly~1", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			// The earlier format named one branch for the whole lock; it is
			// refused rather than read with the branch dropped.
			name: "branch on the lock",
			in: `{
				"branch": "nightly",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			// A top-level branch is refused even with the branch on every
			// row, rather than read and ignored.
			name: "branch on the lock and on the source",
			in: `{
				"branch": "main",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "unknown member",
			in: `{
				"registry": "ghcr.io/vulsio/vuls-data-db",
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "unknown source member",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567", "approved": {}}
				]
			}`,
			wantErr: true,
		},
		{
			name: "hold is not a boolean",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567", "hold": "true"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "no sources",
			in: `{
				"sources": [

				]
			}`,
			wantErr: true,
		},
		{
			name: "empty name",
			in: `{
				"sources": [
					{"name": "", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "duplicate name",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"},
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata-2", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "missing repository",
			in: `{
				"sources": [
					{"name": "alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository without tag",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository with digest",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository host ..",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "../vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository host .",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "./vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository without host",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository host only",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository with uppercase path",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/Vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository with empty path component",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio//vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "repository with invalid tag",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:alpha[", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "tag too long",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "duplicate repository",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"},
					{"name": "alma-errata-2", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789abcdef0123456789abcdef01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "short commit",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "uppercase commit",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "0123456789ABCDEF0123456789ABCDEF01234567"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "branch name as commit",
			in: `{
				"sources": [
					{"name": "alma-errata", "repository": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "branch": "nightly", "commit": "nightly"}
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
