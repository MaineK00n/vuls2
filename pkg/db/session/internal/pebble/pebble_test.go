package pebble_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	pebbledb "github.com/cockroachdb/pebble"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

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
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	pebbleSession "github.com/MaineK00n/vuls2/pkg/db/session/internal/pebble"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/test"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/util"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/MaineK00n/vuls2/pkg/version"
)

func TestConnection_Open(t *testing.T) {
	type fields struct {
		Config *pebbleSession.Config
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
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
		Config *pebbleSession.Config
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}

			if err := c.Close(); (err != nil) != tt.wantErr {
				t.Errorf("Connection.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnection_GetMetadata(t *testing.T) {
	type fields struct {
		Config *pebbleSession.Config
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			want: &dbTypes.Metadata{
				SchemaVersion: pebbleSession.SchemaVersion,
				CreatedBy:     version.String(),
				LastModified:  time.Now(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
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
		Config *pebbleSession.Config
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				metadata: dbTypes.Metadata{
					SchemaVersion: pebbleSession.SchemaVersion,
					CreatedBy:     "vuls (devel)",
					LastModified:  time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
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
		Config *pebbleSession.Config
	}
	type args struct {
		root string
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				root: "testdata/fixtures/alma-small/alma-errata",
			},
			want: map[string][]byte{
				"metadata\x00db":                                               fmt.Appendf(nil, `{"schema_version":0,"created_by":"vuls (devel)","last_modified":"%s"}`, time.Now().UTC().Format(time.RFC3339Nano)),
				"vulnerability\x00root\x00ALSA-2019:3708":                      []byte(`{"id":"ALSA-2019:3708","advisories":["ALSA-2019:3708"],"vulnerabilities":["CVE-2019-2510","CVE-2019-2537"],"ecosystems":["alma:8"],"data_sources":["alma-errata"]}`),
				"vulnerability\x00advisory\x00ALSA-2019:3708":                  []byte(`{"alma-errata":{"ALSA-2019:3708":[{"content":{"id":"ALSA-2019:3708"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability\x00vulnerability\x00CVE-2019-2510":              []byte(`{"alma-errata":{"ALSA-2019:3708":[{"content":{"id":"CVE-2019-2510"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"vulnerability\x00vulnerability\x00CVE-2019-2537":              []byte(`{"alma-errata":{"ALSA-2019:3708":[{"content":{"id":"CVE-2019-2537"},"segments":[{"ecosystem":"alma:8"}]}]}}`),
				"alma:8\x00detection\x00ALSA-2019:3708":                        []byte(`{"alma-errata":[{"criteria":{"operator":"OR","criterions":[{"type":"version","version":{"vulnerable":true,"package":{"type":"binary","binary":{"name":"mariadb-devel:10.3::Judy","architectures":["i686"]}}}}]}}]}`),
				"alma:8\x00index\x00mariadb-devel:10.3::Judy":                  []byte(`["ALSA-2019:3708"]`),
				"datasource\x00alma-errata":                                    []byte(`{"id":"alma-errata","name":"AlmaLinux Errata","raw":[{"url":"ghcr.io/vulsio/vuls-data-db:vuls-data-raw-alma-errata","commit":"23144d94cd39ad0d4499ab3684749b4f8e5fb092","date":"2025-11-14T13:23:03Z"}],"extracted":{"url":"ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata"}}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &pebbleSession.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if err := c.Initialize(); err != nil {
				t.Fatalf("initialize db. error = %v", err)
			}

			if err := c.Put(tt.args.root); (err != nil) != tt.wantErr {
				t.Errorf("Connection.Put() error = %v, wantErr %v", err, tt.wantErr)
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
		Config *pebbleSession.Config
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
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
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
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
		Config *pebbleSession.Config
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
				Config: &pebbleSession.Config{
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
				Config: &pebbleSession.Config{
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
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
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
		Config *pebbleSession.Config
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
				Config: &pebbleSession.Config{
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
				Config: &pebbleSession.Config{
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
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
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
		Config *pebbleSession.Config
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			want: []ecosystemTypes.Ecosystem{"alma:8"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
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
		Config *pebbleSession.Config
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
		wantErr bool
	}{
		{
			name:    "ecosystem not found",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				ecosystem: "ECOSYSTEM-NOT-EXISTS",
				query:     "mariadb-devel:10.3::Judy",
			},
			wantErr: true,
		},
		{
			name:    "query not found",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
			args: args{
				ecosystem: "alma:8",
				query:     "PACKAGE-NOT-EXISTS",
			},
			wantErr: true,
		},
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			fields: fields{
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
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
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			got, err := c.GetIndex(tt.args.ecosystem, tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetIndex() error = %v, wantErr %v", err, tt.wantErr)
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
		Config *pebbleSession.Config
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
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
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
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
		Config *pebbleSession.Config
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
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
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
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
		Config *pebbleSession.Config
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
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
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
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

func TestConnection_DeleteAll(t *testing.T) {
	type fields struct {
		Config *pebbleSession.Config
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
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(session.Config{
				Type: "pebble",
				Path: tt.fields.Config.Path,
				Options: session.StorageOptions{
					Pebble: tt.fields.Config.Options,
				},
			}, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			c := &pebbleSession.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if err := c.DeleteAll(); (err != nil) != tt.wantErr {
				t.Errorf("Connection.DeleteAll() error = %v, wantErr %v", err, tt.wantErr)
			}

			iter, err := c.Conn().NewIter(nil)
			if err != nil {
				t.Fatalf("new iterator. error = %v", err)
			}
			defer iter.Close()

			var keys []string
			for iter.First(); iter.Valid(); iter.Next() {
				keys = append(keys, string(iter.Key()))
			}
			if len(keys) > 0 {
				t.Errorf("Connection.DeleteAll() keys still exist: %v", keys)
			}
		})
	}
}

func TestConnection_Initialize(t *testing.T) {
	type fields struct {
		Config *pebbleSession.Config
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "happy",
			fields: fields{
				Config: &pebbleSession.Config{Path: filepath.Join(t.TempDir(), "vuls.db")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &pebbleSession.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if err := c.Initialize(); (err != nil) != tt.wantErr {
				t.Errorf("Connection.Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Pebble doesn't need bucket initialization, so no keys should exist
			got, err := walkDB(c.Conn())
			if err != nil {
				t.Fatalf("walk db. error = %v", err)
			}

			if len(got) > 0 {
				t.Errorf("Connection.Initialize() unexpected db state: %v", got)
			}
		})
	}
}

func walkDB(db *pebbledb.DB) (map[string][]byte, error) {
	m := make(map[string][]byte)

	iter, err := db.NewIter(nil)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		val, err := iter.ValueAndErr()
		if err != nil {
			return nil, err
		}
		v := make([]byte, len(val))
		copy(v, val)
		m[string(iter.Key())] = v
	}

	if err := iter.Error(); err != nil {
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
		case k == "metadata\x00db":
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
		case strings.HasPrefix(k, "vulnerability\x00root\x00"):
			var w, g pebbleSession.VulnerabilityRoot
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
		case strings.HasPrefix(k, "vulnerability\x00advisory\x00"):
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
		case strings.HasPrefix(k, "vulnerability\x00vulnerability\x00"):
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
		case strings.Contains(k, "\x00detection\x00"):
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
		case strings.Contains(k, "\x00index\x00"):
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
		case strings.HasPrefix(k, "datasource\x00"):
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
			if string(wantbs) != string(gotbs) {
				es = append(es, fmt.Errorf("value for %q is unexpected. expected: %q, got: %q", k, string(wantbs), string(gotbs)))
			}
		}

		delete(want, k)
	}

	var missing []string
	for k := range want {
		missing = append(missing, k)
	}
	if len(missing) > 0 {
		return fmt.Errorf("%v is not found", missing)
	}

	return errors.Join(es...)
}

// Verify that unused imports are silenced.
var _ = pebble.ErrNotFound
