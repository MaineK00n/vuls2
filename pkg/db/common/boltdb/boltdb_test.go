package boltdb_test

import (
	"encoding/json/v2"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"testing"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	versoncriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	criterionpackage "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/common/boltdb"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	"github.com/MaineK00n/vuls2/pkg/db/common/util"
	"github.com/google/go-cmp/cmp"
)

func TestConnection_Open(t *testing.T) {
	type fields struct {
		Config *boltdb.Config
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &boltdb.Connection{
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
		Config *boltdb.Config
		cache  *util.Cache
	}
	tests := []struct {
		name    string
		fields  fields
		want    *dbTypes.Metadata
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		fields  fields
		args    args
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		queries    []string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   iter.Seq2[dbTypes.VulnerabilityData, error]
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			got := c.GetVulnerabilityData(tt.args.searchType, tt.args.queries...)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Connection.GetVulnerabilityData(). (-expected +got):\n%s", diff)
			}
		})
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
		fields  fields
		args    args
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		fields  fields
		args    args
		want    *dbTypes.VulnerabilityData
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		args    args
		want    map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
		wantErr bool
	}{
		{
			name: "not found",
			fields: fields{
				Config: &boltdb.Config{
					Path: filepath.Join(t.TempDir(), "boltdb_test.db"),
				},
			},
			args: args{
				id: "ADV-NOT-EXISTS",
			},
			wantErr: true,
		},
		{
			name: "happy",
			fields: fields{
				Config: &boltdb.Config{
					Path: filepath.Join(t.TempDir(), "boltdb_test.db"),
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
								ID: "ALSA-2019:3708",
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
					Path: filepath.Join(t.TempDir(), "boltdb_test.db"),
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
								},
							},
						},
					})
					return c
				}(),
			},
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
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := populateDB(tt.fields.Config.Path); err != nil {
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
		fields  fields
		args    args
		want    map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
		wantErr bool
	}{
		{
			name: "not found",
			fields: fields{
				Config: &boltdb.Config{
					Path: filepath.Join(t.TempDir(), "boltdb_test.db"),
				},
			},
			args: args{
				id: "VULN-NOT-EXISTS",
			},
			wantErr: true,
		},
		{
			name: "happy",
			fields: fields{
				Config: &boltdb.Config{
					Path: filepath.Join(t.TempDir(), "boltdb_test.db"),
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
						},
					},
				},
			},
		},
		{
			name: "cache first",
			fields: fields{
				Config: &boltdb.Config{
					Path: filepath.Join(t.TempDir(), "boltdb_test.db"),
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
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := populateDB(tt.fields.Config.Path); err != nil {
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
		fields  fields
		want    []ecosystemTypes.Ecosystem
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		fields  fields
		args    args
		want    map[dataTypes.RootID][]string
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		fields  fields
		args    args
		want    map[sourceTypes.SourceID][]conditionTypes.Condition
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		fields  fields
		want    []datasourceTypes.DataSource
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		fields  fields
		args    args
		want    *datasourceTypes.DataSource
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		fields  fields
		args    args
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func populateDB(dbpath string) error {
	c := &boltdb.Connection{
		Config: &boltdb.Config{
			Path: dbpath,
		},
	}
	if err := c.Open(); err != nil {
		return err
	}
	defer c.Close()

	if err := c.Initialize(); err != nil {
		return err
	}

	d := dataTypes.Data{
		ID: "ALSA-2019:3708",
		Advisories: []advisoryTypes.Advisory{
			{
				Content: advisoryContentTypes.Content{
					ID: "ALSA-2019:3708",
				},
			},
		},
		Vulnerabilities: []vulnerabilityTypes.Vulnerability{
			{
				Content: vulnerabilityContentTypes.Content{
					ID: "CVE-2019-2510",
				},
			},
			{
				Content: vulnerabilityContentTypes.Content{
					ID: "CVE-2019-2537",
				},
			},
		},
		Detections: []detectionTypes.Detection{
			{
				Ecosystem: "alma:8",
				Conditions: []conditionTypes.Condition{
					{
						Criteria: criteriaTypes.Criteria{
							Operator: criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: []criterionTypes.Criterion{
								{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &versoncriterionTypes.Criterion{
										Vulnerable: true,
										Package: criterionpackage.Package{
											Type: criterionpackage.PackageTypeBinary,
											Binary: &binaryTypes.Package{
												Name: "mariadb-devel:10.3::Judy",
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
		DataSource: sourceTypes.Source{
			ID: "alma-errata",
			Raws: []string{
				"fixtures/8/ALSA/2019/ALSA-2019:3708.json",
			},
		},
	}

	dataPath := filepath.Join(filepath.Dir(dbpath), "fixture", "data")
	if err := os.MkdirAll(dataPath, 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dataPath, fmt.Sprintf("%s.json", d.ID)), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := json.MarshalWrite(f, d); err != nil {
		return err
	}
	if err := c.PutVulnerabilityData(filepath.Dir(dataPath)); err != nil {
		return err
	}

	return nil

}
