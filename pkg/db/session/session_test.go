package session_test

import (
	"encoding/json/v2"
	"fmt"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pkg/errors"
	"go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/boltdb"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/cache"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/rdb"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/redis"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/test"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
)

func TestConfig_New(t *testing.T) {
	type fields struct {
		Type      string
		Path      string
		Debug     bool
		Options   session.StorageOptions
		WithCache bool
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "happy",
			fields: fields{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := session.Config{
				Type:      tt.fields.Type,
				Path:      tt.fields.Path,
				Debug:     tt.fields.Debug,
				Options:   tt.fields.Options,
				WithCache: tt.fields.WithCache,
			}
			got, err := c.New()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got.Storage() == nil {
				t.Errorf("Config.New() db connection is nil")
			}

			if got.Cache() != nil {
				t.Errorf("Config.New() cache is not nil")
			}
		})
	}
}

func TestSession_DB(t *testing.T) {
	type fields struct {
		dbConn session.Storage
		_      *cache.Cache
	}
	tests := []struct {
		name   string
		fields fields
		want   session.Storage
	}{
		{
			name: "happy",
			fields: fields{
				dbConn: &boltdb.Connection{Config: &boltdb.Config{Path: "vuls.db", Options: bbolt.DefaultOptions}},
			},
			want: &boltdb.Connection{Config: &boltdb.Config{Path: "vuls.db", Options: bbolt.DefaultOptions}},
		},
		{
			name: "nil",
			fields: fields{
				dbConn: nil,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c session.Session
			c.SetStorage(tt.fields.dbConn)

			if got := c.Storage(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Conn.DB() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_Cache(t *testing.T) {
	type fields struct {
		_     session.Storage
		cache *cache.Cache
	}
	tests := []struct {
		name   string
		fields fields
		want   *cache.Cache
	}{
		{
			name: "happy",
			fields: fields{
				cache: &cache.Cache{},
			},
			want: &cache.Cache{},
		},
		{
			name: "nil",
			fields: fields{
				cache: nil,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c session.Session
			c.SetCache(tt.fields.cache)

			if got := c.Cache(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Conn.Cache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSchemaVersion(t *testing.T) {
	type args struct {
		t string
	}
	tests := []struct {
		name    string
		args    args
		want    uint
		wantErr bool
	}{
		{
			name: "boltdb",
			args: args{
				t: "boltdb",
			},
			want: boltdb.SchemaVersion,
		},
		{
			name: "redis",
			args: args{
				t: "redis",
			},
			want: redis.SchemaVersion,
		},
		{
			name: "sqlite3",
			args: args{
				t: "sqlite3",
			},
			want: rdb.SchemaVersion,
		},
		{
			name: "mysql",
			args: args{
				t: "mysql",
			},
			want: rdb.SchemaVersion,
		},
		{
			name: "postgres",
			args: args{
				t: "postgres",
			},
			want: rdb.SchemaVersion,
		},
		{
			name: "unknown",
			args: args{
				t: "unknown",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := session.SchemaVersion(tt.args.t)
			if (err != nil) != tt.wantErr {
				t.Errorf("SchemaVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SchemaVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_GetVulnerabilityData(t *testing.T) {
	type args struct {
		searchType dbTypes.SearchType
		filter     dbTypes.Filter
		queries    []string
	}
	tests := []struct {
		name    string
		fixture string
		config  session.Config
		args    args
		want    iter.Seq2[string, error]
	}{
		{
			name:    "non-existent id",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchRoot,
				filter: dbTypes.Filter{
					Contents: dbTypes.AllFilterContentTypes(),
				},
				queries: []string{"ROOT-NOT-EXISTS"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("", errors.Wrapf(errors.Wrapf(dbTypes.ErrNotFoundRoot, "vulnerability -> root -> %s not found", "ROOT-NOT-EXISTS"), "get vulnerability data by root id: %s", "ROOT-NOT-EXISTS")) {
					return
				}
			},
		},
		{
			name:    "happy",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchRoot,
				filter: dbTypes.Filter{
					Contents: dbTypes.AllFilterContentTypes(),
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-root/CVE-2019-2510/happy.json", nil) {
					return
				}
			},
		},
		{
			name:    "no advisories",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchRoot,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeVulnerabilities,
						dbTypes.FilterContentTypeDetections,
						dbTypes.FilterContentTypeDataSources,
					},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-root/CVE-2019-2510/no-advisories.json", nil) {
					return
				}
			},
		},
		{
			name:    "no vulnerabilities",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchRoot,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeAdvisories,
						dbTypes.FilterContentTypeDetections,
						dbTypes.FilterContentTypeDataSources,
					},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-root/CVE-2019-2510/no-vulnerabilities.json", nil) {
					return
				}
			},
		},
		{
			name:    "no detections",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchRoot,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeAdvisories,
						dbTypes.FilterContentTypeVulnerabilities,
						dbTypes.FilterContentTypeDataSources,
					},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-root/CVE-2019-2510/no-detections.json", nil) {
					return
				}
			},
		},
		{
			name:    "no datasources",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchRoot,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeAdvisories,
						dbTypes.FilterContentTypeVulnerabilities,
						dbTypes.FilterContentTypeDetections,
					},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-root/CVE-2019-2510/no-datasources.json", nil) {
					return
				}
			},
		},
		{
			name:    "only detections",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchRoot,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeDetections,
					},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-root/CVE-2019-2510/only-detections.json", nil) {
					return
				}
			},
		},
		{
			name:    "datasource filter",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchRoot,
				filter: dbTypes.Filter{
					Contents:    dbTypes.AllFilterContentTypes(),
					DataSources: []sourceTypes.SourceID{"redhat-vex"},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-root/CVE-2019-2510/datasource-filter.json", nil) {
					return
				}
			},
		},
		{
			name:    "ecosystem filter",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchRoot,
				filter: dbTypes.Filter{
					Contents:   dbTypes.AllFilterContentTypes(),
					Ecosystems: []ecosystemTypes.Ecosystem{"ubuntu:18.04"},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-root/CVE-2019-2510/ecosystem-filter.json", nil) {
					return
				}
			},
		},
		{
			name:    "root id filter",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchRoot,
				filter: dbTypes.Filter{
					Contents: dbTypes.AllFilterContentTypes(),
					RootIDs:  []dataTypes.RootID{"CVE-2019-2510", "ALSA-2019:3708"},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-root/CVE-2019-2510/root-id-filter.json", nil) {
					return
				}
			},
		},
		{
			name:    "non-existent id",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchAdvisory,
				filter: dbTypes.Filter{
					Contents: dbTypes.AllFilterContentTypes(),
				},
				queries: []string{"ADV-NOT-EXISTS"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("", errors.Wrapf(errors.Wrapf(errors.Wrapf(dbTypes.ErrNotFoundAdvisory, "vulnerability -> advisory -> %s not found", "ADV-NOT-EXISTS"), "get advisory from db"), "get vulnerability data by advisory id: %s", "ADV-NOT-EXISTS")) {
					return
				}
			},
		},
		{
			name:    "happy",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchAdvisory,
				filter: dbTypes.Filter{
					Contents: dbTypes.AllFilterContentTypes(),
				},
				queries: []string{"RHSA-2019:2511"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-advisory/RHSA-2019%3A2511/happy.json", nil) {
					return
				}
			},
		},
		{
			name:    "no advisories",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchAdvisory,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeVulnerabilities,
						dbTypes.FilterContentTypeDetections,
						dbTypes.FilterContentTypeDataSources,
					},
				},
				queries: []string{"RHSA-2019:2511"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-advisory/RHSA-2019%3A2511/no-advisories.json", nil) {
					return
				}
			},
		},
		{
			name:    "no vulnerabilities",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchAdvisory,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeAdvisories,
						dbTypes.FilterContentTypeDetections,
						dbTypes.FilterContentTypeDataSources,
					},
				},
				queries: []string{"RHSA-2019:2511"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-advisory/RHSA-2019%3A2511/no-vulnerabilities.json", nil) {
					return
				}
			},
		},
		{
			name:    "no detections",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchAdvisory,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeAdvisories,
						dbTypes.FilterContentTypeVulnerabilities,
						dbTypes.FilterContentTypeDataSources,
					},
				},
				queries: []string{"RHSA-2019:2511"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-advisory/RHSA-2019%3A2511/no-detections.json", nil) {
					return
				}
			},
		},
		{
			name:    "no datasources",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchAdvisory,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeAdvisories,
						dbTypes.FilterContentTypeVulnerabilities,
						dbTypes.FilterContentTypeDetections,
					},
				},
				queries: []string{"RHSA-2019:2511"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-advisory/RHSA-2019%3A2511/no-datasources.json", nil) {
					return
				}
			},
		},
		{
			name:    "only detections",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchAdvisory,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeDetections,
					},
				},
				queries: []string{"RHSA-2019:2511"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-advisory/RHSA-2019%3A2511/only-detections.json", nil) {
					return
				}
			},
		},
		{
			name:    "datasource filter",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchAdvisory,
				filter: dbTypes.Filter{
					Contents:    dbTypes.AllFilterContentTypes(),
					DataSources: []sourceTypes.SourceID{"redhat-vex"},
				},
				queries: []string{"RHSA-2019:2511"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-advisory/RHSA-2019%3A2511/datasource-filter.json", nil) {
					return
				}
			},
		},
		{
			name:    "ecosystem filter",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchAdvisory,
				filter: dbTypes.Filter{
					Contents:   dbTypes.AllFilterContentTypes(),
					Ecosystems: []ecosystemTypes.Ecosystem{"redhat:8", "ubuntu:18.04"},
				},
				queries: []string{"RHSA-2019:2511"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-advisory/RHSA-2019%3A2511/ecosystem-filter.json", nil) {
					return
				}
			},
		},
		{
			name:    "root id filter",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchAdvisory,
				filter: dbTypes.Filter{
					Contents: dbTypes.AllFilterContentTypes(),
					RootIDs:  []dataTypes.RootID{"CVE-2019-2510"},
				},
				queries: []string{"RHSA-2019:2511"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-advisory/RHSA-2019%3A2511/root-id-filter.json", nil) {
					return
				}
			},
		},
		{
			name:    "non-existent id",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchVulnerability,
				filter: dbTypes.Filter{
					Contents: dbTypes.AllFilterContentTypes(),
				},
				queries: []string{"VULN-NOT-EXISTS"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("", errors.Wrapf(errors.Wrapf(errors.Wrapf(dbTypes.ErrNotFoundVulnerability, "vulnerability -> vulnerability -> %s not found", "VULN-NOT-EXISTS"), "get vulnerability from db"), "get vulnerability data by vulnerability id: %s", "VULN-NOT-EXISTS")) {
					return
				}
			},
		},
		{
			name:    "happy",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchVulnerability,
				filter: dbTypes.Filter{
					Contents: dbTypes.AllFilterContentTypes(),
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-vulnerability/CVE-2019-2510/happy.json", nil) {
					return
				}
			},
		},
		{
			name:    "no advisories",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchVulnerability,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeVulnerabilities,
						dbTypes.FilterContentTypeDetections,
						dbTypes.FilterContentTypeDataSources,
					},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-vulnerability/CVE-2019-2510/no-advisories.json", nil) {
					return
				}
			},
		},
		{
			name:    "no vulnerabilities",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchVulnerability,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeAdvisories,
						dbTypes.FilterContentTypeDetections,
						dbTypes.FilterContentTypeDataSources,
					},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-vulnerability/CVE-2019-2510/no-vulnerabilities.json", nil) {
					return
				}
			},
		},
		{
			name:    "no detections",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchVulnerability,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeAdvisories,
						dbTypes.FilterContentTypeVulnerabilities,
						dbTypes.FilterContentTypeDataSources,
					},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-vulnerability/CVE-2019-2510/no-detections.json", nil) {
					return
				}
			},
		},
		{
			name:    "no datasources",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchVulnerability,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeAdvisories,
						dbTypes.FilterContentTypeVulnerabilities,
						dbTypes.FilterContentTypeDetections,
					},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-vulnerability/CVE-2019-2510/no-datasources.json", nil) {
					return
				}
			},
		},
		{
			name:    "only detections",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchVulnerability,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeDetections,
					},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-vulnerability/CVE-2019-2510/only-detections.json", nil) {
					return
				}
			},
		},
		{
			name:    "datasource filter",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchVulnerability,
				filter: dbTypes.Filter{
					Contents:    dbTypes.AllFilterContentTypes(),
					DataSources: []sourceTypes.SourceID{"alma-errata"},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-vulnerability/CVE-2019-2510/datasource-filter.json", nil) {
					return
				}
			},
		},
		{
			name:    "ecosystem filter",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchVulnerability,
				filter: dbTypes.Filter{
					Contents:   dbTypes.AllFilterContentTypes(),
					Ecosystems: []ecosystemTypes.Ecosystem{"redhat:8", "alma:8"},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-vulnerability/CVE-2019-2510/ecosystem-filter.json", nil) {
					return
				}
			},
		},
		{
			name:    "root id filter",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchVulnerability,
				filter: dbTypes.Filter{
					Contents: dbTypes.AllFilterContentTypes(),
					RootIDs:  []dataTypes.RootID{"ALSA-2019:3708"},
				},
				queries: []string{"CVE-2019-2510"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-vulnerability/CVE-2019-2510/root-id-filter.json", nil) {
					return
				}
			},
		},
		{
			name:    "non-existent id (no results)",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchPackage,
				filter: dbTypes.Filter{
					Contents: dbTypes.AllFilterContentTypes(),
				},
				queries: []string{"redhat:8", "PKG-NOT-EXISTS"},
			},
			want: func(yield func(string, error) bool) {},
		},
		{
			name:    "happy",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchPackage,
				filter: dbTypes.Filter{
					Contents: dbTypes.AllFilterContentTypes(),
				},
				queries: []string{"redhat:8", "mysql:8.0::mecab"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2510/happy.json", nil) {
					return
				}
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2624/happy.json", nil) {
					return
				}
			},
		},
		{
			name:    "no advisories",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchPackage,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeVulnerabilities,
						dbTypes.FilterContentTypeDetections,
						dbTypes.FilterContentTypeDataSources,
					},
				},
				queries: []string{"redhat:8", "mysql:8.0::mecab"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2510/no-advisories.json", nil) {
					return
				}
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2624/no-advisories.json", nil) {
					return
				}
			},
		},
		{
			name:    "no vulnerabilities",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchPackage,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeAdvisories,
						dbTypes.FilterContentTypeDetections,
						dbTypes.FilterContentTypeDataSources,
					},
				},
				queries: []string{"redhat:8", "mysql:8.0::mecab"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2510/no-vulnerabilities.json", nil) {
					return
				}
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2624/no-vulnerabilities.json", nil) {
					return
				}
			},
		},
		{
			name:    "no detections",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchPackage,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeAdvisories,
						dbTypes.FilterContentTypeVulnerabilities,
						dbTypes.FilterContentTypeDataSources,
					},
				},
				queries: []string{"redhat:8", "mysql:8.0::mecab"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2510/no-detections.json", nil) {
					return
				}
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2624/no-detections.json", nil) {
					return
				}
			},
		},
		{
			name:    "no datasources",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchPackage,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeAdvisories,
						dbTypes.FilterContentTypeVulnerabilities,
						dbTypes.FilterContentTypeDetections,
					},
				},
				queries: []string{"redhat:8", "mysql:8.0::mecab"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2510/no-datasources.json", nil) {
					return
				}
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2624/no-datasources.json", nil) {
					return
				}
			},
		},
		{
			name:    "only detections",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchPackage,
				filter: dbTypes.Filter{
					Contents: []dbTypes.FilterContentType{
						dbTypes.FilterContentTypeDetections,
					},
				},
				queries: []string{"redhat:8", "mysql:8.0::mecab"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2510/only-detections.json", nil) {
					return
				}
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2624/only-detections.json", nil) {
					return
				}
			},
		},
		{
			name:    "datasource filter",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchPackage,
				filter: dbTypes.Filter{
					Contents:    dbTypes.AllFilterContentTypes(),
					DataSources: []sourceTypes.SourceID{"redhat-vex"},
				},
				queries: []string{"redhat:8", "mysql:8.0::mecab"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2510/datasource-filter.json", nil) {
					return
				}
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2624/datasource-filter.json", nil) {
					return
				}
			},
		},
		{
			name:    "ecosystem filter",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchPackage,
				filter: dbTypes.Filter{
					Contents:   dbTypes.AllFilterContentTypes(),
					Ecosystems: []ecosystemTypes.Ecosystem{"redhat:8", "ubuntu:18.04"},
				},
				queries: []string{"redhat:8", "mysql:8.0::mecab"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2510/ecosystem-filter.json", nil) {
					return
				}
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2624/ecosystem-filter.json", nil) {
					return
				}
			},
		},
		{
			name:    "root id filter",
			fixture: "testdata/fixtures/get-vulnerability-data",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			args: args{
				searchType: dbTypes.SearchPackage,
				filter: dbTypes.Filter{
					Contents: dbTypes.AllFilterContentTypes(),
					RootIDs:  []dataTypes.RootID{"ALSA-2019:3708", "CVE-2019-2510"},
				},
				queries: []string{"redhat:8", "mysql:8.0::mecab"},
			},
			want: func(yield func(string, error) bool) {
				if !yield("testdata/golden/get-vulnerability-data/search-package/redhat%3A8/mysql%3A8.0%3A%3Amecab/CVE-2019-2510/root-id-filter.json", nil) {
					return
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s %s", tt.args.searchType, tt.name), func(t *testing.T) {
			if err := test.PopulateDB(tt.config, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c, err := tt.config.New()
			if err != nil {
				t.Fatalf("new db connection. error = %v", err)
			}

			if err := c.Storage().Open(); err != nil {
				t.Fatalf("open db connection. error = %v", err)
			}
			defer c.Storage().Close()

			if tt.config.WithCache {
				defer c.Cache().Close()
			}

			got := c.GetVulnerabilityData(tt.args.searchType, tt.args.filter, tt.args.queries...)

			wnext, wstop := iter.Pull2(tt.want)
			defer wstop()
			gnext, gstop := iter.Pull2(sorted(got))
			defer gstop()

			for {
				wantpath, wantErr, wantOk := wnext()
				got, gotErr, gotOk := gnext()

				if !wantOk || !gotOk {
					if wantOk != gotOk {
						t.Errorf("Conn.GetVulnerabilityData() length mismatch: want hasNext=%v, got hasNext=%v", wantOk, gotOk)
					}
					break
				}

				switch {
				case wantErr == nil && gotErr != nil:
					t.Errorf("Conn.GetVulnerabilityData() unexpected error: %v", gotErr)
				case wantErr != nil && gotErr == nil:
					t.Errorf("Conn.GetVulnerabilityData() expected error has not occurred")
				case wantErr != nil && gotErr != nil:
					if wantErr.Error() != gotErr.Error() {
						t.Errorf("Conn.GetVulnerabilityData() error mismatch: want %v, got %v", wantErr, gotErr)
					}
				default:
					f, err := os.Open(wantpath)
					if err != nil {
						t.Fatalf("open %s. err: %v", wantpath, err)
					}
					defer f.Close()

					var want dbTypes.VulnerabilityData
					if err := json.UnmarshalRead(f, &want); err != nil {
						t.Fatalf("unmarshal %s. err: %v", wantpath, err)
					}

					if diff := cmp.Diff(want, got,
						cmpopts.SortSlices(func(x, y dbTypes.VulnerabilityData) bool { return x.ID < y.ID }),
						cmpopts.SortSlices(func(x, y dbTypes.VulnerabilityDataAdvisory) bool { return x.ID < y.ID }),
						cmpopts.SortSlices(func(x, y dbTypes.VulnerabilityDataVulnerability) bool { return x.ID < y.ID }),
						cmpopts.SortSlices(func(x, y dbTypes.VulnerabilityDataDetection) bool { return x.Ecosystem < y.Ecosystem }),
						cmpopts.SortSlices(func(x, y datasourceTypes.DataSource) bool { return x.ID < y.ID }),
					); diff != "" {
						t.Errorf("Conn.GetVulnerabilityData() data mismatch (-want +got):\n%s", diff)
					}
				}
			}
		})
	}
}

func sorted(i iter.Seq2[dbTypes.VulnerabilityData, error]) iter.Seq2[dbTypes.VulnerabilityData, error] {
	type v struct {
		v1 dbTypes.VulnerabilityData
		v2 error
	}
	m := make(map[string]v)
	for v1, v2 := range i {
		m[v1.ID] = v{v1, v2}
	}

	return func(yield func(dbTypes.VulnerabilityData, error) bool) {
		for _, id := range slices.Sorted(maps.Keys(m)) {
			if !yield(m[id].v1, m[id].v2) {
				return
			}
		}
	}
}

func TestSession_GetAdvisory(t *testing.T) {
	type args struct {
		id advisoryContentTypes.AdvisoryID
	}
	tests := []struct {
		name    string
		fixture string
		config  session.Config
		cache   map[advisoryContentTypes.AdvisoryID]map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
		args    args
		want    map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
		wantErr bool
	}{
		{
			name:    "boltdb",
			fixture: "internal/boltdb/testdata/fixtures/alma-small",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: false,
			},
			args: args{
				id: "ALSA-2019:3708",
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"alma-errata": {
					"ALSA-2019:3708": {
						{
							Content: advisoryContentTypes.Content{
								ID: "ALSA-2019:3708",
							},
							Segments: []segmentTypes.Segment{
								{
									Ecosystem: ecosystemTypes.Ecosystem("alma:8"),
								},
							},
						},
					},
				},
			},
		},
		{
			name:    "boltdb, cache hit",
			fixture: "internal/boltdb/testdata/fixtures/alma-small",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			cache: map[advisoryContentTypes.AdvisoryID]map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"ALSA-2019:3708": {
					"alma-errata": {
						"ALSA-2019:3708": {
							{
								Content: advisoryContentTypes.Content{
									ID: "Cache",
								},
								Segments: []segmentTypes.Segment{
									{
										Ecosystem: ecosystemTypes.Ecosystem("alma:8"),
									},
								},
							},
						},
					},
				},
			},
			args: args{
				id: "ALSA-2019:3708",
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"alma-errata": {
					"ALSA-2019:3708": {
						{
							Content: advisoryContentTypes.Content{
								ID: "Cache",
							},
							Segments: []segmentTypes.Segment{
								{
									Ecosystem: ecosystemTypes.Ecosystem("alma:8"),
								},
							},
						},
					},
				},
			},
		},
		{
			name:    "boltdb, cache miss",
			fixture: "internal/boltdb/testdata/fixtures/alma-small",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			cache: nil,
			args: args{
				id: "ALSA-2019:3708",
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"alma-errata": {
					"ALSA-2019:3708": {
						{
							Content: advisoryContentTypes.Content{
								ID: "ALSA-2019:3708",
							},
							Segments: []segmentTypes.Segment{
								{
									Ecosystem: ecosystemTypes.Ecosystem("alma:8"),
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(tt.config, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c, err := tt.config.New()
			if err != nil {
				t.Fatalf("new db connection. error = %v", err)
			}

			if err := c.Storage().Open(); err != nil {
				t.Fatalf("open db connection. error = %v", err)
			}
			defer c.Storage().Close()

			if tt.config.WithCache {
				defer c.Cache().Close()

				for k, v := range tt.cache {
					c.Cache().StoreAdvisory(k, v)
				}
			}

			got, err := c.GetAdvisory(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Conn.GetAdvisory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Conn.GetAdvisory() = %v, want %v", got, tt.want)
			}

			if tt.config.WithCache {
				m, ok := c.Cache().LoadAdvisory(tt.args.id)
				if !ok {
					t.Errorf("Conn.GetAdvisory() no cache set")
				}

				if !reflect.DeepEqual(m, tt.want) {
					t.Errorf("Conn.GetAdvisory() cache = %v, want %v", m, tt.want)
				}
			}
		})
	}
}

func TestSession_GetVulnerability(t *testing.T) {
	type args struct {
		id vulnerabilityContentTypes.VulnerabilityID
	}
	tests := []struct {
		name    string
		fixture string
		config  session.Config
		cache   map[vulnerabilityContentTypes.VulnerabilityID]map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
		args    args
		want    map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
		wantErr bool
	}{
		{
			name:    "boltdb",
			fixture: "internal/boltdb/testdata/fixtures/alma-small",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: false,
			},
			cache: nil,
			args: args{
				id: "CVE-2019-2510",
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"alma-errata": {
					"ALSA-2019:3708": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "CVE-2019-2510",
							},
							Segments: []segmentTypes.Segment{
								{
									Ecosystem: ecosystemTypes.Ecosystem("alma:8"),
								},
							},
						},
					},
				},
			},
		},
		{
			name:    "boltdb, cache hit",
			fixture: "internal/boltdb/testdata/fixtures/alma-small",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			cache: map[vulnerabilityContentTypes.VulnerabilityID]map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"CVE-2019-2510": {
					"alma-errata": {
						"ALSA-2019:3708": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "Cache",
								},
								Segments: []segmentTypes.Segment{
									{
										Ecosystem: ecosystemTypes.Ecosystem("alma:8"),
									},
								},
							},
						},
					},
				},
			},
			args: args{
				id: "CVE-2019-2510",
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"alma-errata": {
					"ALSA-2019:3708": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "Cache",
							},
							Segments: []segmentTypes.Segment{
								{
									Ecosystem: ecosystemTypes.Ecosystem("alma:8"),
								},
							},
						},
					},
				},
			},
		},
		{
			name:    "boltdb",
			fixture: "internal/boltdb/testdata/fixtures/alma-small",
			config: session.Config{
				Type:      "boltdb",
				Path:      filepath.Join(t.TempDir(), "vuls.db"),
				Options:   session.StorageOptions{BoltDB: bbolt.DefaultOptions},
				WithCache: true,
			},
			cache: nil,
			args: args{
				id: "CVE-2019-2510",
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"alma-errata": {
					"ALSA-2019:3708": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "CVE-2019-2510",
							},
							Segments: []segmentTypes.Segment{
								{
									Ecosystem: ecosystemTypes.Ecosystem("alma:8"),
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(tt.config, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c, err := tt.config.New()
			if err != nil {
				t.Fatalf("new db connection. error = %v", err)
			}

			if err := c.Storage().Open(); err != nil {
				t.Fatalf("open db connection. error = %v", err)
			}
			defer c.Storage().Close()

			if tt.config.WithCache {
				defer c.Cache().Close()

				for k, v := range tt.cache {
					c.Cache().StoreVulnerability(k, v)
				}
			}

			got, err := c.GetVulnerability(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Conn.GetVulnerability() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Conn.GetVulnerability() = %v, want %v", got, tt.want)
			}

			if tt.config.WithCache {
				m, ok := c.Cache().LoadVulnerability(tt.args.id)
				if !ok {
					t.Errorf("Conn.GetVulnerability() no cache set")
				}

				if !reflect.DeepEqual(m, tt.want) {
					t.Errorf("Conn.GetVulnerability() cache = %v, want %v", m, tt.want)
				}
			}
		})
	}
}
