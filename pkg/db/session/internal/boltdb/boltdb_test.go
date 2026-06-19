package boltdb_test

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/boltdb"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/test"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/util"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/MaineK00n/vuls2/pkg/version"
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
	}{
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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

			if c.Conn() == nil {
				t.Errorf("DB Connection is nil")
			}
		})
	}
}

func TestConnection_Close(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		wantErr bool
	}{
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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

			if err := c.Close(); (err != nil) != tt.wantErr {
				t.Errorf("Connection.Close() error = %v, wantErr %v", err, tt.wantErr)
			}

			if _, err := c.Conn().Begin(false); !errors.Is(err, berrors.ErrDatabaseNotOpen) {
				t.Errorf("DB Connection is not closed")
			}
		})
	}
}

func TestConnection_GetMetadata(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		want    *dbTypes.Metadata
		wantErr bool
	}{
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			want: &dbTypes.Metadata{
				SchemaVersion: boltdb.SchemaVersion,
				CreatedBy:     version.String(),
				LastModified:  time.Now(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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

			got, err := c.GetMetadata()
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateApproxTime(3*time.Second)); diff != "" {
				t.Errorf("Connection.GetMetadata(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_PutMetadata(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
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
	}{
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				metadata: dbTypes.Metadata{
					SchemaVersion: boltdb.SchemaVersion,
					CreatedBy:     "vuls (devel)",
					LastModified:  time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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

			if err := c.PutMetadata(tt.args.metadata); (err != nil) != tt.wantErr {
				t.Errorf("Connection.PutMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}

			got, err := c.GetMetadata()
			if err != nil {
				t.Fatalf("get metadata. error = %v", err)
			}
			if diff := cmp.Diff(tt.args.metadata, *got); diff != "" {
				t.Errorf("Connection.GetMetadata(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_Put(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
	}
	type args struct {
		roots []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[string][]byte
		wantErr bool
	}{
		{
			name: "happy",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				roots: []string{"testdata/fixtures/alma-small/alma-errata"},
			},
			want: map[string][]byte{
				"metadata":              nil,
				"metadata -> db":        fmt.Appendf(nil, `{"schema_version":1,"created_by":"vuls (devel)","last_modified":"%s"}`, time.Now().UTC().Format(time.RFC3339Nano)),
				"vulnerability":         nil,
				"vulnerability -> root": nil,
				"vulnerability -> root -> ALSA-2019:3708":         []byte(`{"id":"ALSA-2019:3708","advisories":["ALSA-2019:3708"],"vulnerabilities":["CVE-2019-2510","CVE-2019-2537"],"ecosystems":["alma:8"],"data_sources":["alma-errata"]}`),
				"vulnerability -> advisory":                       nil,
				"vulnerability -> advisory -> ALSA-2019:3708":     []byte(`{"alma-errata":{"ALSA-2019:3708":[{"content":{"id":"ALSA-2019:3708"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> vulnerability":                  nil,
				"vulnerability -> vulnerability -> CVE-2019-2510": []byte(`{"alma-errata":{"ALSA-2019:3708":[{"content":{"id":"CVE-2019-2510"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> vulnerability -> CVE-2019-2537": []byte(`{"alma-errata":{"ALSA-2019:3708":[{"content":{"id":"CVE-2019-2537"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"alma:8":                                      nil,
				"alma:8 -> detection":                         nil,
				"alma:8 -> detection -> ALSA-2019:3708":       []byte(`{"alma-errata":[{"criteria":{"operator":"OR","criterions":[{"type":"version","version":{"vulnerable":true,"package":{"type":"binary","binary":{"name":"mariadb-devel:10.3::Judy","architectures":["i686"]}}}}]}}]}`),
				"alma:8 -> index":                             nil,
				"alma:8 -> index -> mariadb-devel:10.3::Judy": []byte(`["ALSA-2019:3708"]`),
				"datasource":                                  nil,
				"attack":                                      nil,
				"capec":                                       nil,
				"cwe":                                         nil,
				"datasource -> alma-errata":                   []byte(`{"id":"alma-errata","name":"AlmaLinux Errata","raw":[{"url":"ghcr.io/vulsio/vuls-data-db:vuls-data-raw-alma-errata","commit":"23144d94cd39ad0d4499ab3684749b4f8e5fb092","date":"2025-11-14T13:23:03Z"}],"extracted":{"url":"ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata"}}`),
			},
		},
		{
			name: "batch commit",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db"), PutBatchSize: 2},
			},
			args: args{
				roots: []string{"testdata/fixtures/alma-batch/alma-errata"},
			},
			want: map[string][]byte{
				"metadata":              nil,
				"metadata -> db":        fmt.Appendf(nil, `{"schema_version":1,"created_by":"vuls (devel)","last_modified":"%s"}`, time.Now().UTC().Format(time.RFC3339Nano)),
				"vulnerability":         nil,
				"vulnerability -> root": nil,
				"vulnerability -> root -> ALSA-2019:3708":         []byte(`{"id":"ALSA-2019:3708","advisories":["ALSA-2019:3708"],"vulnerabilities":["CVE-2019-2510","CVE-2019-2537"],"ecosystems":["alma:8"],"data_sources":["alma-errata"]}`),
				"vulnerability -> root -> ALSA-2019:4001":         []byte(`{"id":"ALSA-2019:4001","advisories":["ALSA-2019:4001"],"vulnerabilities":["CVE-2019-1001"],"ecosystems":["alma:8"],"data_sources":["alma-errata"]}`),
				"vulnerability -> root -> ALSA-2019:4002":         []byte(`{"id":"ALSA-2019:4002","advisories":["ALSA-2019:4002"],"vulnerabilities":["CVE-2019-1002"],"ecosystems":["alma:8"],"data_sources":["alma-errata"]}`),
				"vulnerability -> advisory":                       nil,
				"vulnerability -> advisory -> ALSA-2019:3708":     []byte(`{"alma-errata":{"ALSA-2019:3708":[{"content":{"id":"ALSA-2019:3708"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> advisory -> ALSA-2019:4001":     []byte(`{"alma-errata":{"ALSA-2019:4001":[{"content":{"id":"ALSA-2019:4001"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> advisory -> ALSA-2019:4002":     []byte(`{"alma-errata":{"ALSA-2019:4002":[{"content":{"id":"ALSA-2019:4002"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> vulnerability":                  nil,
				"vulnerability -> vulnerability -> CVE-2019-2510": []byte(`{"alma-errata":{"ALSA-2019:3708":[{"content":{"id":"CVE-2019-2510"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> vulnerability -> CVE-2019-2537": []byte(`{"alma-errata":{"ALSA-2019:3708":[{"content":{"id":"CVE-2019-2537"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> vulnerability -> CVE-2019-1001": []byte(`{"alma-errata":{"ALSA-2019:4001":[{"content":{"id":"CVE-2019-1001"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> vulnerability -> CVE-2019-1002": []byte(`{"alma-errata":{"ALSA-2019:4002":[{"content":{"id":"CVE-2019-1002"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"alma:8":                                      nil,
				"alma:8 -> detection":                         nil,
				"alma:8 -> detection -> ALSA-2019:3708":       []byte(`{"alma-errata":[{"criteria":{"operator":"OR","criterions":[{"type":"version","version":{"vulnerable":true,"package":{"type":"binary","binary":{"name":"mariadb-devel:10.3::Judy","architectures":["i686"]}}}}]}}]}`),
				"alma:8 -> detection -> ALSA-2019:4001":       []byte(`{"alma-errata":[{"criteria":{"operator":"OR","criterions":[{"type":"version","version":{"vulnerable":true,"package":{"type":"binary","binary":{"name":"libfoo","architectures":["x86_64"]}}}}]}}]}`),
				"alma:8 -> detection -> ALSA-2019:4002":       []byte(`{"alma-errata":[{"criteria":{"operator":"OR","criterions":[{"type":"version","version":{"vulnerable":true,"package":{"type":"binary","binary":{"name":"libbar","architectures":["x86_64"]}}}}]}}]}`),
				"alma:8 -> index":                             nil,
				"alma:8 -> index -> mariadb-devel:10.3::Judy": []byte(`["ALSA-2019:3708"]`),
				"alma:8 -> index -> libfoo":                   []byte(`["ALSA-2019:4001"]`),
				"alma:8 -> index -> libbar":                   []byte(`["ALSA-2019:4002"]`),
				"datasource":                                  nil,
				"attack":                                      nil,
				"capec":                                       nil,
				"cwe":                                         nil,
				"datasource -> alma-errata":                   []byte(`{"id":"alma-errata","name":"AlmaLinux Errata","raw":[{"url":"ghcr.io/vulsio/vuls-data-db:vuls-data-raw-alma-errata","commit":"23144d94cd39ad0d4499ab3684749b4f8e5fb092","date":"2025-11-14T13:23:03Z"}],"extracted":{"url":"ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata"}}`),
			},
		},
		{
			name: "cross-batch index merge",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db"), PutBatchSize: 2},
			},
			args: args{
				roots: []string{"testdata/fixtures/alma-batch-merge/alma-errata"},
			},
			want: map[string][]byte{
				"metadata":              nil,
				"metadata -> db":        fmt.Appendf(nil, `{"schema_version":1,"created_by":"vuls (devel)","last_modified":"%s"}`, time.Now().UTC().Format(time.RFC3339Nano)),
				"vulnerability":         nil,
				"vulnerability -> root": nil,
				"vulnerability -> root -> ALSA-2019:5001":         []byte(`{"id":"ALSA-2019:5001","advisories":["ALSA-2019:5001"],"vulnerabilities":["CVE-2019-5001"],"ecosystems":["alma:8"],"data_sources":["alma-errata"]}`),
				"vulnerability -> root -> ALSA-2019:5002":         []byte(`{"id":"ALSA-2019:5002","advisories":["ALSA-2019:5002"],"vulnerabilities":["CVE-2019-5002"],"ecosystems":["alma:8"],"data_sources":["alma-errata"]}`),
				"vulnerability -> root -> ALSA-2019:5003":         []byte(`{"id":"ALSA-2019:5003","advisories":["ALSA-2019:5003"],"vulnerabilities":["CVE-2019-5003"],"ecosystems":["alma:8"],"data_sources":["alma-errata"]}`),
				"vulnerability -> advisory":                       nil,
				"vulnerability -> advisory -> ALSA-2019:5001":     []byte(`{"alma-errata":{"ALSA-2019:5001":[{"content":{"id":"ALSA-2019:5001"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> advisory -> ALSA-2019:5002":     []byte(`{"alma-errata":{"ALSA-2019:5002":[{"content":{"id":"ALSA-2019:5002"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> advisory -> ALSA-2019:5003":     []byte(`{"alma-errata":{"ALSA-2019:5003":[{"content":{"id":"ALSA-2019:5003"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> vulnerability":                  nil,
				"vulnerability -> vulnerability -> CVE-2019-5001": []byte(`{"alma-errata":{"ALSA-2019:5001":[{"content":{"id":"CVE-2019-5001"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> vulnerability -> CVE-2019-5002": []byte(`{"alma-errata":{"ALSA-2019:5002":[{"content":{"id":"CVE-2019-5002"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability -> vulnerability -> CVE-2019-5003": []byte(`{"alma-errata":{"ALSA-2019:5003":[{"content":{"id":"CVE-2019-5003"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"alma:8":                                nil,
				"alma:8 -> detection":                   nil,
				"alma:8 -> detection -> ALSA-2019:5001": []byte(`{"alma-errata":[{"criteria":{"operator":"OR","criterions":[{"type":"version","version":{"vulnerable":true,"package":{"type":"binary","binary":{"name":"shared-pkg","architectures":["x86_64"]}}}}]}}]}`),
				"alma:8 -> detection -> ALSA-2019:5002": []byte(`{"alma-errata":[{"criteria":{"operator":"OR","criterions":[{"type":"version","version":{"vulnerable":true,"package":{"type":"binary","binary":{"name":"shared-pkg","architectures":["x86_64"]}}}}]}}]}`),
				"alma:8 -> detection -> ALSA-2019:5003": []byte(`{"alma-errata":[{"criteria":{"operator":"OR","criterions":[{"type":"version","version":{"vulnerable":true,"package":{"type":"binary","binary":{"name":"shared-pkg","architectures":["x86_64"]}}}}]}}]}`),
				"alma:8 -> index":                       nil,
				"alma:8 -> index -> shared-pkg":         []byte(`["ALSA-2019:5001","ALSA-2019:5002","ALSA-2019:5003"]`),
				"datasource":                            nil,
				"attack":                                nil,
				"capec":                                 nil,
				"cwe":                                   nil,
				"datasource -> alma-errata":             []byte(`{"id":"alma-errata","name":"AlmaLinux Errata","raw":[{"url":"ghcr.io/vulsio/vuls-data-db:vuls-data-raw-alma-errata","commit":"23144d94cd39ad0d4499ab3684749b4f8e5fb092","date":"2025-11-14T13:23:03Z"}],"extracted":{"url":"ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata"}}`),
			},
		},
		{
			name: "microsoft",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				roots: []string{"testdata/fixtures/microsoft-small/microsoft-bulletin"},
			},
			want: map[string][]byte{
				"metadata":                                        nil,
				"metadata -> db":                                  fmt.Appendf(nil, `{"schema_version":1,"created_by":"vuls (devel)","last_modified":"%s"}`, time.Now().UTC().Format(time.RFC3339Nano)),
				"vulnerability":                                   nil,
				"vulnerability -> root":                           nil,
				"vulnerability -> root -> MS17-010":               []byte(`{"id":"MS17-010","advisories":["MS17-010"],"vulnerabilities":["CVE-2017-0143","CVE-2017-0144","CVE-2017-0145","CVE-2017-0146","CVE-2017-0147","CVE-2017-0148"],"ecosystems":["microsoft"],"data_sources":["microsoft-bulletin"]}`),
				"vulnerability -> advisory":                       nil,
				"vulnerability -> advisory -> MS17-010":           []byte(`{"microsoft-bulletin":{"MS17-010":[{"content":{"id":"MS17-010","title":"Security Update for Microsoft Windows SMB Server","severity":[{"type":"vendor","source":"security@microsoft.com","vendor":"Critical"}],"references":[{"source":"security@microsoft.com","url":"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"}],"published":"2017-03-14T00:00:00Z","optional":{"impact":"Remote Code Execution"}},"segments":[{"ecosystem":"microsoft","tag":"Windows 10 for x64-based Systems"}]}]}}`),
				"vulnerability -> vulnerability":                  nil,
				"vulnerability -> vulnerability -> CVE-2017-0143": []byte(`{"microsoft-bulletin":{"MS17-010":[{"content":{"id":"CVE-2017-0143","references":[{"source":"security@microsoft.com","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0143"}]},"segments":[{"ecosystem":"microsoft","tag":"Windows 10 for x64-based Systems"}]}]}}`),
				"vulnerability -> vulnerability -> CVE-2017-0144": []byte(`{"microsoft-bulletin":{"MS17-010":[{"content":{"id":"CVE-2017-0144","references":[{"source":"security@microsoft.com","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144"}]},"segments":[{"ecosystem":"microsoft","tag":"Windows 10 for x64-based Systems"}]}]}}`),
				"vulnerability -> vulnerability -> CVE-2017-0145": []byte(`{"microsoft-bulletin":{"MS17-010":[{"content":{"id":"CVE-2017-0145","references":[{"source":"security@microsoft.com","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0145"}]},"segments":[{"ecosystem":"microsoft","tag":"Windows 10 for x64-based Systems"}]}]}}`),
				"vulnerability -> vulnerability -> CVE-2017-0146": []byte(`{"microsoft-bulletin":{"MS17-010":[{"content":{"id":"CVE-2017-0146","references":[{"source":"security@microsoft.com","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0146"}]},"segments":[{"ecosystem":"microsoft","tag":"Windows 10 for x64-based Systems"}]}]}}`),
				"vulnerability -> vulnerability -> CVE-2017-0147": []byte(`{"microsoft-bulletin":{"MS17-010":[{"content":{"id":"CVE-2017-0147","references":[{"source":"security@microsoft.com","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0147"}]},"segments":[{"ecosystem":"microsoft","tag":"Windows 10 for x64-based Systems"}]}]}}`),
				"vulnerability -> vulnerability -> CVE-2017-0148": []byte(`{"microsoft-bulletin":{"MS17-010":[{"content":{"id":"CVE-2017-0148","references":[{"source":"security@microsoft.com","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0148"}]},"segments":[{"ecosystem":"microsoft","tag":"Windows 10 for x64-based Systems"}]}]}}`),
				"microsoft":                          nil,
				"microsoft -> detection":             nil,
				"microsoft -> detection -> MS17-010": []byte(`{"microsoft-bulletin":[{"criteria":{"operator":"OR","criterions":[{"type":"kb","kb":{"product":"Windows 10 for x64-based Systems","kb_id":"4012606"}}]},"tag":"Windows 10 for x64-based Systems"}]}`),
				"microsoft -> index":                 nil,
				"microsoft -> index -> Windows 10 for x64-based Systems": []byte(`["MS17-010"]`),
				"microsoft -> kb":                  nil,
				"microsoft -> kb -> 4012606":       []byte(`{"microsoft-bulletin":{"kb_id":"4012606","url":"https://support.microsoft.com/help/4012606","products":["Internet Explorer 11 on Windows 10 for x64-based Systems","Microsoft Edge on Windows 10 for x64-based Systems","Microsoft XML Core Services 3.0 on Windows 10 for x64-based Systems","Windows 10 for x64-based Systems"],"data_source":{"id":"microsoft-bulletin","raws":["vuls-data-raw-microsoft-bulletin/17/MS17-006.json","vuls-data-raw-microsoft-bulletin/17/MS17-007.json","vuls-data-raw-microsoft-bulletin/17/MS17-008.json","vuls-data-raw-microsoft-bulletin/17/MS17-009.json","vuls-data-raw-microsoft-bulletin/17/MS17-010.json","vuls-data-raw-microsoft-bulletin/17/MS17-011.json","vuls-data-raw-microsoft-bulletin/17/MS17-012.json","vuls-data-raw-microsoft-bulletin/17/MS17-013.json","vuls-data-raw-microsoft-bulletin/17/MS17-016.json","vuls-data-raw-microsoft-bulletin/17/MS17-017.json","vuls-data-raw-microsoft-bulletin/17/MS17-018.json","vuls-data-raw-microsoft-bulletin/17/MS17-021.json","vuls-data-raw-microsoft-bulletin/17/MS17-022.json"]}}}`),
				"datasource":                       nil,
				"attack":                           nil,
				"capec":                            nil,
				"cwe":                              nil,
				"datasource -> microsoft-bulletin": []byte(`{"id":"microsoft-bulletin","name":"Microsoft Security Bulletin","raw":[{"url":"ghcr.io/vulsio/vuls-data-db:vuls-data-raw-microsoft-bulletin","commit":"3dd51f6ac89db13efedf13fadd1b7f99b174bc5d","date":"2026-04-01T04:02:55Z"}]}`),
			},
		},
		{
			name: "microsoft-kb-only",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				roots: []string{"testdata/fixtures/microsoft-small/microsoft-msuc"},
			},
			want: map[string][]byte{
				"metadata":                       nil,
				"metadata -> db":                 fmt.Appendf(nil, `{"schema_version":1,"created_by":"vuls (devel)","last_modified":"%s"}`, time.Now().UTC().Format(time.RFC3339Nano)),
				"vulnerability":                  nil,
				"vulnerability -> root":          nil,
				"vulnerability -> advisory":      nil,
				"vulnerability -> vulnerability": nil,
				"microsoft":                      nil,
				"microsoft -> kb":                nil,
				"microsoft -> kb -> 5000854":     []byte(`{"microsoft-msuc":{"kb_id":"5000854","url":"https://support.microsoft.com/help/5000854","updates":[{"update_id":"a328f9a9-f5c2-4734-a4ae-d01785fb4711","title":"2021-03 Cumulative Update Preview for Windows Server 2019 for x64-based Systems (KB5000854)","architecture":"AMD64","classification":"Updates","products":["WindowsServer2019"],"superseded_by":[{"kb_id":"5001384","update_id":"41498488-597f-44ea-9c26-dbb65bec2ffa"}],"catalog_url":""}],"data_source":{"id":"microsoft-msuc","raws":["vuls-data-raw-microsoft-msuc/a328f9a9-f5c2-4734-a4ae-d01785fb4711.json"]}}}`),
				"datasource":                     nil,
				"attack":                         nil,
				"capec":                          nil,
				"cwe":                            nil,
				"datasource -> microsoft-msuc":   []byte(`{"id":"microsoft-msuc","name":"Microsoft Update Catalog","raw":[{"url":"ghcr.io/vulsio/vuls-data-db:vuls-data-raw-microsoft-msuc","commit":"0000000000000000000000000000000000000000","date":"2026-04-01T00:00:00Z"}]}`),
			},
		},
		{
			// Two consecutive Put calls (different data sources) write the same
			// (ecosystem, package) key, so test:multi -> index -> shared-pkg must
			// contain the union of rootIDs in sorted order.
			name: "multi-source merge",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				roots: []string{
					"testdata/fixtures/multi-put-merge/source-a",
					"testdata/fixtures/multi-put-merge/source-b",
				},
			},
			want: map[string][]byte{
				"metadata":                                nil,
				"metadata -> db":                          fmt.Appendf(nil, `{"schema_version":1,"created_by":"vuls (devel)","last_modified":"%s"}`, time.Now().UTC().Format(time.RFC3339Nano)),
				"vulnerability":                           nil,
				"vulnerability -> root":                   nil,
				"vulnerability -> root -> ROOT-A":         []byte(`{"id":"ROOT-A","advisories":["ROOT-A"],"vulnerabilities":["CVE-A"],"ecosystems":["test:multi"],"data_sources":["source-a"]}`),
				"vulnerability -> root -> ROOT-B":         []byte(`{"id":"ROOT-B","advisories":["ROOT-B"],"vulnerabilities":["CVE-B"],"ecosystems":["test:multi"],"data_sources":["source-b"]}`),
				"vulnerability -> advisory":               nil,
				"vulnerability -> advisory -> ROOT-A":     []byte(`{"source-a":{"ROOT-A":[{"content":{"id":"ROOT-A"},"segments":[{"ecosystem":"test:multi"}]}]}}`),
				"vulnerability -> advisory -> ROOT-B":     []byte(`{"source-b":{"ROOT-B":[{"content":{"id":"ROOT-B"},"segments":[{"ecosystem":"test:multi"}]}]}}`),
				"vulnerability -> vulnerability":          nil,
				"vulnerability -> vulnerability -> CVE-A": []byte(`{"source-a":{"ROOT-A":[{"content":{"id":"CVE-A"},"segments":[{"ecosystem":"test:multi"}]}]}}`),
				"vulnerability -> vulnerability -> CVE-B": []byte(`{"source-b":{"ROOT-B":[{"content":{"id":"CVE-B"},"segments":[{"ecosystem":"test:multi"}]}]}}`),
				"test:multi":                              nil,
				"test:multi -> detection":                 nil,
				"test:multi -> detection -> ROOT-A":       []byte(`{"source-a":[{"criteria":{"operator":"OR","criterions":[{"type":"version","version":{"vulnerable":true,"package":{"type":"binary","binary":{"name":"shared-pkg","architectures":["x86_64"]}}}}]}}]}`),
				"test:multi -> detection -> ROOT-B":       []byte(`{"source-b":[{"criteria":{"operator":"OR","criterions":[{"type":"version","version":{"vulnerable":true,"package":{"type":"binary","binary":{"name":"shared-pkg","architectures":["x86_64"]}}}}]}}]}`),
				"test:multi -> index":                     nil,
				"test:multi -> index -> shared-pkg":       []byte(`["ROOT-A","ROOT-B"]`),
				"datasource":                              nil,
				"attack":                                  nil,
				"capec":                                   nil,
				"cwe":                                     nil,
				"datasource -> source-a":                  []byte(`{"id":"source-a","name":"Source A","raw":[{"url":"ghcr.io/vulsio/source-a"}]}`),
				"datasource -> source-b":                  []byte(`{"id":"source-b","name":"Source B","raw":[{"url":"ghcr.io/vulsio/source-b"}]}`),
			},
		},
		{
			name: "cpe",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				roots: []string{"testdata/fixtures/nvd-cpe/nvd-feed-cve-v2"},
			},
			want: map[string][]byte{
				"metadata":                                        nil,
				"metadata -> db":                                  fmt.Appendf(nil, `{"schema_version":1,"created_by":"vuls (devel)","last_modified":"%s"}`, time.Now().UTC().Format(time.RFC3339Nano)),
				"vulnerability":                                   nil,
				"vulnerability -> root":                           nil,
				"vulnerability -> root -> CVE-2024-0028":          []byte(`{"id":"CVE-2024-0028","vulnerabilities":["CVE-2024-0028"],"ecosystems":["cpe"],"data_sources":["nvd-feed-cve-v2"]}`),
				"vulnerability -> advisory":                       nil,
				"vulnerability -> vulnerability":                  nil,
				"vulnerability -> vulnerability -> CVE-2024-0028": []byte(`{"nvd-feed-cve-v2":{"CVE-2024-0028":[{"content":{"id":"CVE-2024-0028","description":"In Audio Service, there is a possible way to obtain MAC addresses of nearby Bluetooth devices due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.","severity":[{"type":"cvss_v31","source":"134c704f-9b21-4f2e-91b3-4a467353bcc0","cvss_v31":{"vector":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N","base_score":5.5,"base_severity":"MEDIUM","temporal_score":5.5,"temporal_severity":"MEDIUM","environmental_score":5.5,"environmental_severity":"MEDIUM"}}],"cwe":[{"source":"134c704f-9b21-4f2e-91b3-4a467353bcc0","cwe":["CWE-862"]}],"references":[{"source":"nvd.nist.gov","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-0028"},{"source":"security@android.com","url":"https://source.android.com/security/bulletin/android-16"}],"published":"2025-09-05T17:15:33.27Z","modified":"2025-09-08T16:38:34.34Z"},"segments":[{"ecosystem":"cpe"}]}]}}`),
				"cpe":                               nil,
				"cpe -> detection":                  nil,
				"cpe -> detection -> CVE-2024-0028": []byte(`{"nvd-feed-cve-v2":[{"criteria":{"operator":"OR","criterias":[{"operator":"OR","criterias":[{"operator":"OR","criterias":[{"operator":"OR","criterions":[{"type":"cpe","cpe":{"vulnerable":true,"fix_status":{"class":"unknown"},"cpe":"cpe:2.3:o:google:android:16.0:*:*:*:*:*:*:*"}}]}]}]}]}}]}`),
				"cpe -> index":                      nil,
				"cpe -> index -> o:google:android":  []byte(`["CVE-2024-0028"]`),
				"datasource":                        nil,
				"attack":                            nil,
				"capec":                             nil,
				"cwe":                               nil,
				"datasource -> nvd-feed-cve-v2":     []byte(`{"id":"nvd-feed-cve-v2","name":"NVD Feed CVE v2"}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if err := c.Initialize(); err != nil {
				t.Fatalf("initialize db. error = %v", err)
			}

			var putErr error
			for _, root := range tt.args.roots {
				if putErr = c.Put(root); putErr != nil {
					break
				}
			}
			if (putErr != nil) != tt.wantErr {
				t.Errorf("Connection.Put() error = %v, wantErr %v", putErr, tt.wantErr)
			}

			got, err := walkDB(c.Conn())
			if err != nil {
				t.Fatalf("walk db. error = %v", err)
			}

			if err := compare(tt.want, got); err != nil {
				t.Errorf("Connection.Put() unexpected db state: %v", err)
			}
		})
	}
}

func TestConnection_GetRoot(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
	}
	type args struct {
		id dataTypes.RootID
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		args    args
		want    dbTypes.VulnerabilityData
		wantErr bool
	}{
		{
			name:    "not found",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				id: "ROOT-NOT-EXISTS",
			},
			wantErr: true,
		},
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				id: "ALSA-2019:3708",
			},
			want: dbTypes.VulnerabilityData{
				ID: "ALSA-2019:3708",
				Advisories: []dbTypes.VulnerabilityDataAdvisory{
					{
						ID: "ALSA-2019:3708",
					},
				},
				Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
					{
						ID: "CVE-2019-2510",
					},
					{
						ID: "CVE-2019-2537",
					},
				},
				Detections: []dbTypes.VulnerabilityDataDetection{
					{
						Ecosystem: "alma:8",
					},
				},
				DataSources: []datasourceTypes.DataSource{
					{
						ID: "alma-errata",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		want    []ecosystemTypes.Ecosystem
		wantErr bool
	}{
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			want: []ecosystemTypes.Ecosystem{"alma:8"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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

func TestConnection_GetIndex(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
	}
	type args struct {
		ecosystem ecosystemTypes.Ecosystem
		query     string
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		args    args
		want    []dataTypes.RootID
		wantErr error
	}{
		{
			name:    "ecosystem not found",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				ecosystem: "ECOSYSTEM-NOT-EXISTS",
				query:     "mariadb-devel:10.3::Judy",
			},
			wantErr: dbTypes.ErrNotFoundEcosystem,
		},
		{
			name:    "query not found",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				ecosystem: "alma:8",
				query:     "PACKAGE-NOT-EXISTS",
			},
			wantErr: dbTypes.ErrNotFoundIndex,
		},
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				ecosystem: "alma:8",
				query:     "mariadb-devel:10.3::Judy",
			},
			want: []dataTypes.RootID{"ALSA-2019:3708"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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

			got, err := c.GetIndex(tt.args.ecosystem, tt.args.query)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Connection.GetIndex() error = %v, want errors.Is %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("Connection.GetIndex() unexpected error = %v", err)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Connection.GetIndex(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_GetDetection(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
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
	}{
		{
			name:    "ecosystem not found",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				ecosystem: "ECOSYSTEM-NOT-EXISTS",
				rootID:    "ALSA-2019:3708",
			},
			wantErr: true,
		},
		{
			name:    "rootID not found",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				ecosystem: "alma:8",
				rootID:    "ROOT-NOT-EXISTS",
			},
			wantErr: true,
		},
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				ecosystem: "alma:8",
				rootID:    "ALSA-2019:3708",
			},
			want: map[sourceTypes.SourceID][]conditionTypes.Condition{
				"alma-errata": {
					{
						Criteria: criteriaTypes.Criteria{
							Operator: criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: []criterionTypes.Criterion{
								{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Vulnerable: true,
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
												Name:          "mariadb-devel:10.3::Judy",
												Architectures: []string{"i686"},
											},
										},
									},
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
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		want    []datasourceTypes.DataSource
		wantErr bool
	}{
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			want: []datasourceTypes.DataSource{
				{
					ID:   "alma-errata",
					Name: new("AlmaLinux Errata"),
					Raw: []repositoryTypes.Repository{
						{
							URL:    "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-alma-errata",
							Commit: "23144d94cd39ad0d4499ab3684749b4f8e5fb092",
							Date:   new(time.Date(2025, time.November, 14, 13, 23, 03, 0, time.UTC)),
						},
					},
					Extracted: &repositoryTypes.Repository{
						URL: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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
	}
	type args struct {
		id sourceTypes.SourceID
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		args    args
		want    datasourceTypes.DataSource
		wantErr bool
	}{
		{
			name:    "not found",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				id: "SOURCE-NOT-EXISTS",
			},
			wantErr: true,
		},
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				id: "alma-errata",
			},
			want: datasourceTypes.DataSource{
				ID:   "alma-errata",
				Name: new("AlmaLinux Errata"),
				Raw: []repositoryTypes.Repository{
					{
						URL:    "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-alma-errata",
						Commit: "23144d94cd39ad0d4499ab3684749b4f8e5fb092",
						Date:   new(time.Date(2025, time.November, 14, 13, 23, 03, 0, time.UTC)),
					},
				},
				Extracted: &repositoryTypes.Repository{
					URL: "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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

func TestConnection_GetMicrosoftKB(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
	}
	type args struct {
		kbid string
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		args    args
		want    map[sourceTypes.SourceID]microsoftkbTypes.KB
		wantErr error
	}{
		{
			name:    "ecosystem not found",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				kbid: "4012606",
			},
			wantErr: dbTypes.ErrNotFoundEcosystem,
		},
		{
			name:    "kbid not found",
			fixture: "testdata/fixtures/microsoft-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				kbid: "KBID-NOT-EXISTS",
			},
			wantErr: dbTypes.ErrNotFoundMicrosoftKB,
		},
		{
			name:    "happy",
			fixture: "testdata/fixtures/microsoft-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				kbid: "4012606",
			},
			want: map[sourceTypes.SourceID]microsoftkbTypes.KB{
				sourceTypes.SourceID("microsoft-bulletin"): {
					KBID: "4012606",
					URL:  "https://support.microsoft.com/help/4012606",
					Products: []string{
						"Internet Explorer 11 on Windows 10 for x64-based Systems",
						"Microsoft Edge on Windows 10 for x64-based Systems",
						"Microsoft XML Core Services 3.0 on Windows 10 for x64-based Systems",
						"Windows 10 for x64-based Systems",
					},
					DataSource: sourceTypes.Source{
						ID:   sourceTypes.SourceID("microsoft-bulletin"),
						Raws: []string{"vuls-data-raw-microsoft-bulletin/17/MS17-006.json", "vuls-data-raw-microsoft-bulletin/17/MS17-007.json", "vuls-data-raw-microsoft-bulletin/17/MS17-008.json", "vuls-data-raw-microsoft-bulletin/17/MS17-009.json", "vuls-data-raw-microsoft-bulletin/17/MS17-010.json", "vuls-data-raw-microsoft-bulletin/17/MS17-011.json", "vuls-data-raw-microsoft-bulletin/17/MS17-012.json", "vuls-data-raw-microsoft-bulletin/17/MS17-013.json", "vuls-data-raw-microsoft-bulletin/17/MS17-016.json", "vuls-data-raw-microsoft-bulletin/17/MS17-017.json", "vuls-data-raw-microsoft-bulletin/17/MS17-018.json", "vuls-data-raw-microsoft-bulletin/17/MS17-021.json", "vuls-data-raw-microsoft-bulletin/17/MS17-022.json"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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

			got, err := c.GetMicrosoftKB(tt.args.kbid)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Connection.GetMicrosoftKB() error = %v, want errors.Is %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("Connection.GetMicrosoftKB() unexpected error = %v", err)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Connection.GetMicrosoftKB(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestConnection_DeleteAll(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
	}
	tests := []struct {
		name    string
		fixture string
		fields  fields
		wantErr bool
	}{
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "boltdb",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
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

			if err := c.DeleteAll(); (err != nil) != tt.wantErr {
				t.Errorf("Connection.DeleteAll() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Conn().View(func(tx *bbolt.Tx) error {
				var bs []string
				if err := tx.ForEach(func(name []byte, _ *bbolt.Bucket) error {
					bs = append(bs, string(name))
					return nil
				}); err != nil {
					return err
				}
				if len(bs) > 0 {
					return fmt.Errorf("buckets still exist: %s", bs)
				}
				return nil
			}); err != nil {
				t.Errorf("Connection.DeleteAll() error = %v", err)
			}
		})
	}
}

func TestConnection_Initialize(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
	}
	tests := []struct {
		name    string
		fields  fields
		want    map[string][]byte
		wantErr bool
	}{
		{
			name: "happy",
			fields: fields{
				Config: &boltdb.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			want: map[string][]byte{
				"metadata":                       nil,
				"vulnerability":                  nil,
				"vulnerability -> root":          nil,
				"vulnerability -> advisory":      nil,
				"vulnerability -> vulnerability": nil,
				"datasource":                     nil,
				"attack":                         nil,
				"capec":                          nil,
				"cwe":                            nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &boltdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if err := c.Initialize(); (err != nil) != tt.wantErr {
				t.Errorf("Connection.Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}

			got, err := walkDB(c.Conn())
			if err != nil {
				t.Fatalf("walk db. error = %v", err)
			}

			if err := compare(tt.want, got); err != nil {
				t.Errorf("Connection.Initialize() unexpected db state: %v", err)
			}
		})
	}
}

func walkDB(db *bbolt.DB) (map[string][]byte, error) {
	m := make(map[string][]byte)
	if err := db.View(func(tx *bbolt.Tx) error {
		var fn func(path string, b *bbolt.Bucket) error
		fn = func(path string, b *bbolt.Bucket) error {
			if err := b.ForEach(func(k, v []byte) error {
				m[fmt.Sprintf("%s -> %s", path, k)] = v

				if sub := b.Bucket(k); sub != nil {
					if err := fn(fmt.Sprintf("%s -> %s", path, k), sub); err != nil {
						return err
					}
				}

				return nil
			}); err != nil {
				return err
			}
			return nil
		}

		return tx.ForEach(func(name []byte, b *bbolt.Bucket) error {
			m[string(name)] = nil
			if err := fn(string(name), b); err != nil {
				return err
			}
			return nil
		})
	}); err != nil {
		return nil, err
	}
	return m, nil
}

func compare(want, got map[string][]byte) error {
	var es []error

	for k, gotbs := range got {
		wantbs, ok := want[k]
		if !ok {
			es = append(es, fmt.Errorf("%q is unexpected", k))
			continue
		}

		switch {
		case k == "metadata -> db":
			var w, g dbTypes.Metadata
			if err := util.Unmarshal(wantbs, &w); err != nil {
				return fmt.Errorf("want unmarshal %q: %w", k, err)
			}
			if err := util.Unmarshal(gotbs, &g); err != nil {
				es = append(es, fmt.Errorf("got unmarshal %q: %w", k, err))
				continue
			}

			if diff := cmp.Diff(w, g, cmpopts.EquateApproxTime(3*time.Second)); diff != "" {
				es = append(es, fmt.Errorf("value for %q is unexpected. (-expected +got):\n%s", k, diff))
			}
		case strings.HasPrefix(k, "vulnerability -> root -> "):
			var w, g boltdb.VulnerabilityRoot
			if err := util.Unmarshal(wantbs, &w); err != nil {
				return fmt.Errorf("want unmarshal %q: %w", k, err)
			}
			if err := util.Unmarshal(gotbs, &g); err != nil {
				es = append(es, fmt.Errorf("got unmarshal %q: %w", k, err))
				continue
			}

			if diff := cmp.Diff(w, g); diff != "" {
				es = append(es, fmt.Errorf("value for %q is unexpected. (-expected +got):\n%s", k, diff))
			}
		case strings.HasPrefix(k, "vulnerability -> advisory -> "):
			var w, g map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
			if err := util.Unmarshal(wantbs, &w); err != nil {
				return fmt.Errorf("want unmarshal %q: %w", k, err)
			}
			if err := util.Unmarshal(gotbs, &g); err != nil {
				es = append(es, fmt.Errorf("got unmarshal %q: %w", k, err))
				continue
			}

			if diff := cmp.Diff(w, g); diff != "" {
				es = append(es, fmt.Errorf("value for %q is unexpected. (-expected +got):\n%s", k, diff))
			}
		case strings.HasPrefix(k, "vulnerability -> vulnerability -> "):
			var w, g map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
			if err := util.Unmarshal(wantbs, &w); err != nil {
				return fmt.Errorf("want unmarshal %q: %w", k, err)
			}
			if err := util.Unmarshal(gotbs, &g); err != nil {
				es = append(es, fmt.Errorf("got unmarshal %q: %w", k, err))
				continue
			}

			if diff := cmp.Diff(w, g); diff != "" {
				es = append(es, fmt.Errorf("value for %q is unexpected. (-expected +got):\n%s", k, diff))
			}
		case strings.Contains(k, "-> detection ->"):
			var w, g map[sourceTypes.SourceID][]conditionTypes.Condition
			if err := util.Unmarshal(wantbs, &w); err != nil {
				return fmt.Errorf("want unmarshal %q: %w", k, err)
			}
			if err := util.Unmarshal(gotbs, &g); err != nil {
				es = append(es, fmt.Errorf("got unmarshal %q: %w", k, err))
				continue
			}

			if diff := cmp.Diff(w, g); diff != "" {
				es = append(es, fmt.Errorf("value for %q is unexpected. (-expected +got):\n%s", k, diff))
			}
		case strings.Contains(k, "-> index ->"):
			var w, g []string
			if err := util.Unmarshal(wantbs, &w); err != nil {
				return fmt.Errorf("want unmarshal %q: %w", k, err)
			}
			if err := util.Unmarshal(gotbs, &g); err != nil {
				es = append(es, fmt.Errorf("got unmarshal %q: %w", k, err))
				continue
			}

			if diff := cmp.Diff(w, g); diff != "" {
				es = append(es, fmt.Errorf("value for %q is unexpected. (-expected +got):\n%s", k, diff))
			}
		case strings.HasPrefix(k, "datasource -> "):
			var w, g datasourceTypes.DataSource
			if err := util.Unmarshal(wantbs, &w); err != nil {
				return fmt.Errorf("want unmarshal %q: %w", k, err)
			}
			if err := util.Unmarshal(gotbs, &g); err != nil {
				es = append(es, fmt.Errorf("got unmarshal %q: %w", k, err))
				continue
			}

			if diff := cmp.Diff(w, g); diff != "" {
				es = append(es, fmt.Errorf("value for %q is unexpected. (-expected +got):\n%s", k, diff))
			}
		default:
			if !bytes.Equal(wantbs, gotbs) {
				es = append(es, fmt.Errorf("value for %q is unexpected. expected: %q, got: %q", k, string(wantbs), string(gotbs)))
			}
		}

		delete(want, k)
	}
	if len(want) > 0 {
		return fmt.Errorf("%v is not found", slices.Collect(maps.Keys(want)))
	}

	return errors.Join(es...)
}
