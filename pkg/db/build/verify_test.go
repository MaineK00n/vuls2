package build

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

	dbAdd "github.com/MaineK00n/vuls2/pkg/db/add"
	dbInit "github.com/MaineK00n/vuls2/pkg/db/init"
	"github.com/MaineK00n/vuls2/pkg/db/session"
)

// TestVerify checks a db against a lock directly: in Build, a duplicate id
// already fails at add, so no build case reaches a failing verify.
func TestVerify(t *testing.T) {
	tests := []struct {
		name    string
		db      []string // datasource.json of each source added to the db
		lock    Lock
		ids     []sourceTypes.SourceID
		wantErr string
	}{
		{
			name: "every source at its lock commit",
			db: []string{
				`{
					"id": "alpha",
					"extracted": {"commit": "1111111111111111111111111111111111111111"}
				}`,
				`{
					"id": "beta",
					"extracted": {"commit": "2222222222222222222222222222222222222222"}
				}`,
			},
			lock: Lock{Sources: []Source{
				{Name: "alpha", Commit: "1111111111111111111111111111111111111111"},
				{Name: "beta", Commit: "2222222222222222222222222222222222222222"},
			}},
			ids: []sourceTypes.SourceID{"alpha", "beta"},
		},
		{
			name: "datasource at another commit",
			db: []string{
				`{
					"id": "alpha",
					"extracted": {"commit": "2222222222222222222222222222222222222222"}
				}`,
			},
			lock: Lock{Sources: []Source{
				{Name: "alpha", Commit: "1111111111111111111111111111111111111111"},
			}},
			ids:     []sourceTypes.SourceID{"alpha"},
			wantErr: `alpha: datasource "alpha" has commit "2222222222222222222222222222222222222222", lock has "1111111111111111111111111111111111111111"`,
		},
		{
			name: "datasource without an extracted commit",
			db: []string{
				`{
					"id": "alpha"
				}`,
			},
			lock: Lock{Sources: []Source{
				{Name: "alpha", Commit: "1111111111111111111111111111111111111111"},
			}},
			ids:     []sourceTypes.SourceID{"alpha"},
			wantErr: `alpha: datasource "alpha" has commit "", lock has "1111111111111111111111111111111111111111"`,
		},
		{
			name: "datasource missing from the db",
			db: []string{
				`{
					"id": "alpha",
					"extracted": {"commit": "1111111111111111111111111111111111111111"}
				}`,
			},
			lock: Lock{Sources: []Source{
				{Name: "alpha", Commit: "1111111111111111111111111111111111111111"},
				{Name: "beta", Commit: "2222222222222222222222222222222222222222"},
			}},
			ids:     []sourceTypes.SourceID{"alpha", "beta"},
			wantErr: `beta: datasource "beta" is not in the db`,
		},
		{
			name: "extra datasource in the db",
			db: []string{
				`{
					"id": "alpha",
					"extracted": {"commit": "1111111111111111111111111111111111111111"}
				}`,
				`{
					"id": "beta",
					"extracted": {"commit": "2222222222222222222222222222222222222222"}
				}`,
			},
			lock: Lock{Sources: []Source{
				{Name: "alpha", Commit: "1111111111111111111111111111111111111111"},
			}},
			ids:     []sourceTypes.SourceID{"alpha"},
			wantErr: "db has 2 datasources, lock has 1",
		},
		{
			name: "two sources with the same datasource id",
			db: []string{
				`{
					"id": "alpha",
					"extracted": {"commit": "1111111111111111111111111111111111111111"}
				}`,
			},
			lock: Lock{Sources: []Source{
				{Name: "alpha", Commit: "1111111111111111111111111111111111111111"},
				{Name: "delta", Commit: "1111111111111111111111111111111111111111"},
			}},
			ids:     []sourceTypes.SourceID{"alpha", "alpha"},
			wantErr: `alpha and delta both have datasource id "alpha"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &options{dbtype: "boltdb", storageopts: session.StorageOptions{BoltDB: bolt.DefaultOptions}}
			dbpath := filepath.Join(t.TempDir(), "vuls.db")
			if err := dbInit.Init(dbInit.WithDBType(opts.dbtype), dbInit.WithDBPath(dbpath), dbInit.WithStorageOptions(opts.storageopts)); err != nil {
				t.Fatalf("init db: %v", err)
			}
			for i, ds := range tt.db {
				root := filepath.Join(t.TempDir(), fmt.Sprintf("source-%d", i))
				if err := os.MkdirAll(root, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "datasource.json"), []byte(ds), 0644); err != nil {
					t.Fatal(err)
				}
				if err := dbAdd.Add(root, dbAdd.WithDBType(opts.dbtype), dbAdd.WithDBPath(dbpath), dbAdd.WithStorageOptions(opts.storageopts)); err != nil {
					t.Fatalf("add %s: %v", root, err)
				}
			}

			err := verify(opts, dbpath, tt.lock, tt.ids)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("verify() error = %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("verify() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
