package boltdb_test

import (
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	db "github.com/MaineK00n/vuls2/pkg/db/common"
	"github.com/MaineK00n/vuls2/pkg/db/common/boltdb"
	"github.com/MaineK00n/vuls2/pkg/db/common/internal/test"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	"github.com/MaineK00n/vuls2/pkg/db/common/util"
)

func TestConnection_Open(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); (err != nil) != tt.wantErr {
				t.Errorf("Connection.Open() error = %v, wantErr %v", err, tt.wantErr)
			}
			defer c.Close()
		})
	}
}

func TestConnection_Close(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			if err := c.Close(); (err != nil) != tt.wantErr {
				t.Errorf("Connection.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnection_GetMetadata(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		want    *dbTypes.Metadata
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			got, err := c.GetMetadata()
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Connection.GetMetadata(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_PutMetadata(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	type args struct {
		metadata dbTypes.Metadata
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		args    args
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			if err := c.PutMetadata(tt.args.metadata); (err != nil) != tt.wantErr {
				t.Errorf("Connection.PutMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnection_GetVulnerabilityData(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	type args struct {
		searchType dbTypes.SearchType
		filter     dbTypes.Filter
		queries    []string
	}
	tests := map[string][]struct {
		name     string
		fixture  string
		fields   fields
		args     args
		wantPath string
		wantErr  bool
	}{
		"SearchRoot": {
			{
				name:    "non-existent id",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchRoot,
					filter: dbTypes.Filter{
						Contents: dbTypes.AllFilterContentTypes(),
					},
					queries: []string{"ROOT-NOT-EXISTS"},
				},
				wantErr: true,
			},
			{
				name:    "happy",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchRoot,
					filter: dbTypes.Filter{
						Contents: dbTypes.AllFilterContentTypes(),
					},
					queries: []string{"CVE-2019-2510"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-root/happy.json",
			},
			{
				name:    "no advisories",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-root/no-advisories.json",
			},
			{
				name:    "no vulnerabilities",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-root/no-vulnerabilities.json",
			},
			{
				name:    "no detections",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-root/no-detections.json",
			},
			{
				name:    "no datasources",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-root/no-datasources.json",
			},
			{
				name:    "only detections",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-root/only-detections.json",
			},
			{
				name:    "root id filter",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchRoot,
					filter: dbTypes.Filter{
						Contents: dbTypes.AllFilterContentTypes(),
						RootIDs:  []dataTypes.RootID{"CVE-2019-2510", "ALSA-2019:3708"},
					},
					queries: []string{"CVE-2019-2510"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-root/root-id-filter.json",
			},
			{
				name:    "ecosystem filter",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchRoot,
					filter: dbTypes.Filter{
						Contents:   dbTypes.AllFilterContentTypes(),
						Ecosystems: []ecosystemTypes.Ecosystem{"ubuntu:18.04"},
					},
					queries: []string{"CVE-2019-2510"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-root/ecosystem-filter.json",
			},
		},
		"SearchAdvisory": {
			{
				name:    "non-existent id",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchAdvisory,
					filter: dbTypes.Filter{
						Contents: dbTypes.AllFilterContentTypes(),
					},
					queries: []string{"ADV-NOT-EXISTS"},
				},
				wantErr: true,
			},
			{
				name:    "happy",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchAdvisory,
					filter: dbTypes.Filter{
						Contents: dbTypes.AllFilterContentTypes(),
					},
					queries: []string{"RHSA-2019:2511"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-advisory/happy.json",
			},
			{
				name:    "no advisories",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-advisory/no-advisories.json",
			},
			{
				name:    "no vulnerabilities",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-advisory/no-vulnerabilities.json",
			},
			{
				name:    "no detections",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-advisory/no-detections.json",
			},
			{
				name:    "no datasources",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-advisory/no-datasources.json",
			},
			{
				name:    "only detections",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-advisory/only-detections.json",
			},
			{
				name:    "root id filter",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchAdvisory,
					filter: dbTypes.Filter{
						Contents: dbTypes.AllFilterContentTypes(),
						RootIDs:  []dataTypes.RootID{"CVE-2019-2510"},
					},
					queries: []string{"RHSA-2019:2511"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-advisory/root-id-filter.json",
			},
			{
				name:    "ecosystem filter",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchAdvisory,
					filter: dbTypes.Filter{
						Contents:   dbTypes.AllFilterContentTypes(),
						Ecosystems: []ecosystemTypes.Ecosystem{"redhat:8", "ubuntu:18.04"},
					},
					queries: []string{"RHSA-2019:2511"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-advisory/ecosystem-filter.json",
			},
		},
		"SearchVulnerability": {
			{
				name:    "non-existent id",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchVulnerability,
					filter: dbTypes.Filter{
						Contents: dbTypes.AllFilterContentTypes(),
					},
					queries: []string{"VULN-NOT-EXISTS"},
				},
				wantErr: true,
			},
			{
				name:    "happy",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchVulnerability,
					filter: dbTypes.Filter{
						Contents: dbTypes.AllFilterContentTypes(),
					},
					queries: []string{"CVE-2019-2510"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-vulnerability/happy.json",
			},
			{
				name:    "no advisories",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-vulnerability/no-advisories.json",
			},
			{
				name:    "no vulnerabilities",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-vulnerability/no-vulnerabilities.json",
			},
			{
				name:    "no detections",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-vulnerability/no-detections.json",
			},
			{
				name:    "no datasources",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-vulnerability/no-datasources.json",
			},
			{
				name:    "only detections",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-vulnerability/only-detections.json",
			},
			{
				name:    "root id filter",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchVulnerability,
					filter: dbTypes.Filter{
						Contents: dbTypes.AllFilterContentTypes(),
						RootIDs:  []dataTypes.RootID{"ALSA-2019:3708"},
					},
					queries: []string{"CVE-2019-2510"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-vulnerability/root-id-filter.json",
			},
			{
				name:    "ecosystem filter",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchVulnerability,
					filter: dbTypes.Filter{
						Contents:   dbTypes.AllFilterContentTypes(),
						Ecosystems: []ecosystemTypes.Ecosystem{"redhat:8", "alma:8"},
					},
					queries: []string{"CVE-2019-2510"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-vulnerability/ecosystem-filter.json",
			},
		},
		"SearchPackage": {
			{
				name:    "non-existent id (no results)",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchPackage,
					filter: dbTypes.Filter{
						Contents: dbTypes.AllFilterContentTypes(),
					},
					queries: []string{"redhat:8", "PKG-NOT-EXISTS"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-package/no-data.json",
			},
			{
				name:    "happy",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchPackage,
					filter: dbTypes.Filter{
						Contents: dbTypes.AllFilterContentTypes(),
					},
					queries: []string{"redhat:8", "mysql:8.0::mecab"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-package/happy.json",
			},
			{
				name:    "no advisories",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-package/no-advisories.json",
			},
			{
				name:    "no vulnerabilities",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-package/no-vulnerabilities.json",
			},
			{
				name:    "no detections",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-package/no-detections.json",
			},
			{
				name:    "no datasources",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-package/no-datasources.json",
			},
			{
				name:    "only detections",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
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
				wantPath: "testdata/golden/get-vulnerability-data/search-package/only-detections.json",
			},
			{
				name:    "root id filter",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchPackage,
					filter: dbTypes.Filter{
						Contents: dbTypes.AllFilterContentTypes(),

						RootIDs: []dataTypes.RootID{"ALSA-2019:3708", "CVE-2019-2510"},
					},
					queries: []string{"redhat:8", "mysql:8.0::mecab"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-package/root-id-filter.json",
			},
			{
				name:    "ecosystem filter",
				fixture: "testdata/fixtures/get-vulnerability-data",
				fields: fields{
					Config: &boltdb.Config{
						Path: filepath.Join(t.TempDir(), "vuls.db"),
					},
				},
				args: args{
					searchType: dbTypes.SearchPackage,
					filter: dbTypes.Filter{
						Contents:   dbTypes.AllFilterContentTypes(),
						Ecosystems: []ecosystemTypes.Ecosystem{"redhat:8", "ubuntu:18.04"},
					},
					queries: []string{"redhat:8", "mysql:8.0::mecab"},
				},
				wantPath: "testdata/golden/get-vulnerability-data/search-package/ecosystem-filter.json",
			},
		},
	}
	for group, tts := range tests {
		for _, tt := range tts {
			t.Run(fmt.Sprintf("%s:%s", group, tt.name), func(t *testing.T) {
				if err := test.PopulateDB(db.Config{
					Type: "boltdb",
					Path: tt.fields.Config.Path,
					Options: db.DBOptions{
						BoltDB: tt.fields.Config.Options,
					},
				}, tt.fixture); err != nil {
					t.Fatalf("populate db. error = %v", err)
				}

				c := &boltdb.Connection{
					Config: tt.fields.Config,
				}
				if err := c.Open(); err != nil {
					t.Fatalf("open db. error = %v", err)
				}
				defer c.Close()

				if tt.fields.cache != nil {
					c.SetCache(tt.fields.cache)
				}

				it := c.GetVulnerabilityData(tt.args.searchType, tt.args.filter, tt.args.queries...)
				var got = []dbTypes.VulnerabilityData{}
				for vd, err := range it {
					if tt.wantErr {
						switch err {
						case nil:
							t.Errorf("Connection.GetVulnerabilityData() expected error, but got nil")
						default:
							return
						}
					}
					if err != nil {
						t.Errorf("Connection.GetVulnerabilityData() error = %v", err)
						break
					}

					got = append(got, vd)
				}

				f, err := os.OpenFile(tt.wantPath, os.O_RDONLY, 0o644)
				if err != nil {
					t.Fatalf("open golden file. path: %s, error = %v", tt.wantPath, err)
				}
				defer f.Close()

				var want []dbTypes.VulnerabilityData
				if err := json.UnmarshalRead(f, &want); err != nil {
					t.Fatalf("unmarshal golden file. error = %v", err)
				}

				if diff := cmp.Diff(want, got,
					cmpopts.SortSlices(func(x, y dbTypes.VulnerabilityData) bool { return x.ID < y.ID }),
					cmpopts.SortSlices(func(x, y dbTypes.VulnerabilityDataAdvisory) bool { return x.ID < y.ID }),
					cmpopts.SortSlices(func(x, y dbTypes.VulnerabilityDataVulnerability) bool { return x.ID < y.ID }),
					cmpopts.SortSlices(func(x, y dbTypes.VulnerabilityDataDetection) bool { return x.Ecosystem < y.Ecosystem }),
					cmpopts.SortSlices(func(x, y datasourceTypes.DataSource) bool { return x.ID < y.ID }),
				); diff != "" {
					t.Errorf("Connection.GetVulnerabilityData(). (-expected +got):\n%s", diff)
				}
			})
		}
	}
}

func TestConnection_PutVulnerabilityData(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	type args struct {
		root string
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		args    args
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			if err := c.PutVulnerabilityData(tt.args.root); (err != nil) != tt.wantErr {
				t.Errorf("Connection.PutVulnerabilityData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnection_GetRoot(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	type args struct {
		id dataTypes.RootID
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		args    args
		want    *dbTypes.VulnerabilityData
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			got, err := c.GetRoot(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetRoot() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Connection.GetRoot(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_GetAdvisory(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	type args struct {
		id advisoryContentTypes.AdvisoryID
	}
	tests := []struct {
		name    string
		fields  fields
		fixture string
		args    args
		want    map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
		wantErr bool
	}{
		{
			name: "not found",
			fields: fields{
				Config: &boltdb.Config{
					Path: filepath.Join(t.TempDir(), "vuls.db"),
				},
			},
			fixture: "testdata/fixtures/alma-small",
			args: args{
				id: "ADV-NOT-EXISTS",
			},
			wantErr: true,
		},
		{
			name: "happy",
			fields: fields{
				Config: &boltdb.Config{
					Path: filepath.Join(t.TempDir(), "vuls.db"),
				},
			},
			fixture: "testdata/fixtures/alma-small",
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
			name: "cache first",
			fields: fields{
				Config: &boltdb.Config{
					Path: filepath.Join(t.TempDir(), "vuls.db"),
				},
				cache: func() *util.Cache {
					c := util.NewCache()
					c.StoreAdvisory("ALSA-2019:3708", map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
						"alma-errata": {
							"ALSA-2019:3708": {
								{
									Content: advisoryContentTypes.Content{
										ID:    "ALSA-2019:3708",
										Title: "cache tainted advisory",
									},
									Segments: []segmentTypes.Segment{
										{
											Ecosystem: ecosystemTypes.Ecosystem("alma:8"),
										},
									},
								},
							},
						},
					})
					return c
				}(),
			},
			fixture: "testdata/fixtures/alma-small",
			args: args{
				id: "ALSA-2019:3708",
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"alma-errata": {
					"ALSA-2019:3708": {
						{
							Content: advisoryContentTypes.Content{
								ID:    "ALSA-2019:3708",
								Title: "cache tainted advisory",
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
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			got, err := c.GetAdvisory(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetAdvisory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Connection.GetAdvisory(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_GetVulnerability(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	type args struct {
		id vulnerabilityContentTypes.VulnerabilityID
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		args    args
		want    map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
		wantErr bool
	}{
		{
			name:    "not found",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{
					Path: filepath.Join(t.TempDir(), "vuls.db"),
				},
			},
			args: args{
				id: "VULN-NOT-EXISTS",
			},
			wantErr: true,
		},
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{
					Path: filepath.Join(t.TempDir(), "vuls.db"),
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
			name:    "cache first",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{
					Path: filepath.Join(t.TempDir(), "vuls.db"),
				},
				cache: func() *util.Cache {
					c := util.NewCache()
					c.StoreVulnerability("CVE-2019-2510", map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
						"alma-errata": {
							"ALSA-2019:3708": {
								{
									Content: vulnerabilityContentTypes.Content{
										ID:    "CVE-2019-2510",
										Title: "cache tainted vulnerability",
									},
									Segments: []segmentTypes.Segment{
										{
											Ecosystem: ecosystemTypes.Ecosystem("alma:8"),
										},
									},
								},
							},
						},
					})
					return c
				}(),
			},
			args: args{
				id: "CVE-2019-2510",
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"alma-errata": {
					"ALSA-2019:3708": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID:    "CVE-2019-2510",
								Title: "cache tainted vulnerability",
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
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			got, err := c.GetVulnerability(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetVulnerability() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Connection.GetVulnerability(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_GetEcosystems(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		want    []ecosystemTypes.Ecosystem
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			got, err := c.GetEcosystems()
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetEcosystems() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Connection.GetEcosystems(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_GetIndexes(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	type args struct {
		ecosystem ecosystemTypes.Ecosystem
		queries   []string
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		args    args
		want    map[dataTypes.RootID][]string
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			got, err := c.GetIndexes(tt.args.ecosystem, tt.args.queries...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetIndexes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Connection.GetIndexes(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_GetDetection(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	type args struct {
		ecosystem ecosystemTypes.Ecosystem
		rootID    dataTypes.RootID
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		args    args
		want    map[sourceTypes.SourceID][]conditionTypes.Condition
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			got, err := c.GetDetection(tt.args.ecosystem, tt.args.rootID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetDetection() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Connection.GetDetection(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_GetDataSources(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		want    []datasourceTypes.DataSource
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			got, err := c.GetDataSources()
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetDataSources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Connection.GetDataSources(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_GetDataSource(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	type args struct {
		id sourceTypes.SourceID
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		args    args
		want    *datasourceTypes.DataSource
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			got, err := c.GetDataSource(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetDataSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Connection.GetDataSource(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_PutDataSource(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	type args struct {
		root string
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		args    args
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			if err := c.PutDataSource(tt.args.root); (err != nil) != tt.wantErr {
				t.Errorf("Connection.PutDataSource() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnection_DeleteAll(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			if err := c.DeleteAll(); (err != nil) != tt.wantErr {
				t.Errorf("Connection.DeleteAll() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnection_Initialize(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
		cache  *util.Cache
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(db.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: db.DBOptions{
					BoltDB: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if tt.fields.cache != nil {
				c.SetCache(tt.fields.cache)
			}

			if err := c.Initialize(); (err != nil) != tt.wantErr {
				t.Errorf("Connection.Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
