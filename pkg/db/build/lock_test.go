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
			in:   `{"branch": "nightly", "registry": "ghcr.io/vulsio/vuls-data-db", "sources": [{"name": "alma-errata", "commit": "` + commit + `"}, {"name": "redhat-vex-v1-rhel", "commit": "` + commit + `"}]}`,
			want: build.Lock{
				Branch:   "nightly",
				Registry: "ghcr.io/vulsio/vuls-data-db",
				Sources: []build.Source{
					{Name: "alma-errata", Commit: commit},
					{Name: "redhat-vex-v1-rhel", Commit: commit},
				},
			},
		},
		{
			name: "registry with port",
			in:   `{"branch": "main", "registry": "127.0.0.1:5000/vulsio/vuls-data-db", "sources": [{"name": "alma-errata", "commit": "` + commit + `"}]}`,
			want: build.Lock{
				Branch:   "main",
				Registry: "127.0.0.1:5000/vulsio/vuls-data-db",
				Sources:  []build.Source{{Name: "alma-errata", Commit: commit}},
			},
		},
		{
			name:    "unknown member",
			in:      `{"branch": "nightly", "registry": "ghcr.io/vulsio/vuls-data-db", "vuls2": "nightly", "sources": [{"name": "alma-errata", "commit": "` + commit + `"}]}`,
			wantErr: true,
		},
		{
			name:    "unknown source member",
			in:      `{"branch": "nightly", "registry": "ghcr.io/vulsio/vuls-data-db", "sources": [{"name": "alma-errata", "commit": "` + commit + `", "approved": {}}]}`,
			wantErr: true,
		},
		{
			name:    "missing branch",
			in:      `{"registry": "ghcr.io/vulsio/vuls-data-db", "sources": [{"name": "alma-errata", "commit": "` + commit + `"}]}`,
			wantErr: true,
		},
		{
			name:    "registry with tag",
			in:      `{"branch": "nightly", "registry": "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata", "sources": [{"name": "alma-errata", "commit": "` + commit + `"}]}`,
			wantErr: true,
		},
		{
			name:    "registry with digest",
			in:      `{"branch": "nightly", "registry": "ghcr.io/vulsio/vuls-data-db@sha256:0123", "sources": [{"name": "alma-errata", "commit": "` + commit + `"}]}`,
			wantErr: true,
		},
		{
			name:    "registry without repository",
			in:      `{"branch": "nightly", "registry": "ghcr.io", "sources": [{"name": "alma-errata", "commit": "` + commit + `"}]}`,
			wantErr: true,
		},
		{
			name:    "no sources",
			in:      `{"branch": "nightly", "registry": "ghcr.io/vulsio/vuls-data-db", "sources": []}`,
			wantErr: true,
		},
		{
			name:    "empty name",
			in:      `{"branch": "nightly", "registry": "ghcr.io/vulsio/vuls-data-db", "sources": [{"name": "", "commit": "` + commit + `"}]}`,
			wantErr: true,
		},
		{
			name:    "name with prefix path",
			in:      `{"branch": "nightly", "registry": "ghcr.io/vulsio/vuls-data-db", "sources": [{"name": "vulsio/vuls-data-db:alma-errata", "commit": "` + commit + `"}]}`,
			wantErr: true,
		},
		{
			name:    "duplicate name",
			in:      `{"branch": "nightly", "registry": "ghcr.io/vulsio/vuls-data-db", "sources": [{"name": "alma-errata", "commit": "` + commit + `"}, {"name": "alma-errata", "commit": "` + commit + `"}]}`,
			wantErr: true,
		},
		{
			name:    "short commit",
			in:      `{"branch": "nightly", "registry": "ghcr.io/vulsio/vuls-data-db", "sources": [{"name": "alma-errata", "commit": "0123456"}]}`,
			wantErr: true,
		},
		{
			name:    "uppercase commit",
			in:      `{"branch": "nightly", "registry": "ghcr.io/vulsio/vuls-data-db", "sources": [{"name": "alma-errata", "commit": "` + strings.ToUpper(commit) + `"}]}`,
			wantErr: true,
		},
		{
			name:    "branch name as commit",
			in:      `{"branch": "nightly", "registry": "ghcr.io/vulsio/vuls-data-db", "sources": [{"name": "alma-errata", "commit": "nightly"}]}`,
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

func TestSource_Repository(t *testing.T) {
	got := build.Source{Name: "alma-errata"}.Repository("ghcr.io/vulsio/vuls-data-db")
	if want := "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata"; got != want {
		t.Errorf("Repository() = %q, want %q", got, want)
	}
}
