package rdb_test

import (
	"iter"
	"reflect"
	"testing"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/common/rdb"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

func TestConnection_Open(t *testing.T) {
	type fields struct {
		Config *rdb.Config
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &rdb.Connection{
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
		Config *rdb.Config
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &rdb.Connection{
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
		Config *rdb.Config
	}
	tests := []struct {
		name    string
		fields  fields
		want    *dbTypes.Metadata
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &rdb.Connection{
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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Connection.GetMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnection_PutMetadata(t *testing.T) {
	type fields struct {
		Config *rdb.Config
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
			c := &rdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if err := c.PutMetadata(tt.args.metadata); (err != nil) != tt.wantErr {
				t.Errorf("Connection.PutMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnection_GetVulnerabilityData(t *testing.T) {
	type fields struct {
		Config *rdb.Config
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
			c := &rdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if got := c.GetVulnerabilityData(tt.args.searchType, tt.args.queries...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Connection.GetVulnerabilityData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnection_PutVulnerabilityData(t *testing.T) {
	type fields struct {
		Config *rdb.Config
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
			c := &rdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if err := c.PutVulnerabilityData(tt.args.root); (err != nil) != tt.wantErr {
				t.Errorf("Connection.PutVulnerabilityData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnection_GetRoot(t *testing.T) {
	type fields struct {
		Config *rdb.Config
	}
	type args struct {
		rootID dataTypes.RootID
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
			c := &rdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			got, err := c.GetRoot(tt.args.rootID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetRoot() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Connection.GetRoot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnection_GetAdvisory(t *testing.T) {
	type fields struct {
		Config *rdb.Config
	}
	type args struct {
		advisoryID advisoryContentTypes.AdvisoryID
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &rdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			got, err := c.GetAdvisory(tt.args.advisoryID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetAdvisory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Connection.GetAdvisory() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnection_GetVulnerability(t *testing.T) {
	type fields struct {
		Config *rdb.Config
	}
	type args struct {
		vulnerabilityID vulnerabilityContentTypes.VulnerabilityID
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &rdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			got, err := c.GetVulnerability(tt.args.vulnerabilityID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetVulnerability() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Connection.GetVulnerability() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnection_GetEcosystems(t *testing.T) {
	type fields struct {
		Config *rdb.Config
	}
	tests := []struct {
		name    string
		fields  fields
		want    []ecosystemTypes.Ecosystem
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &rdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close() //nolint:errcheck

			got, err := c.GetEcosystems()
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetEcosystems() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Connection.GetEcosystems() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnection_GetIndexes(t *testing.T) {
	type fields struct {
		Config *rdb.Config
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
			c := &rdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			got, err := c.GetIndexes(tt.args.ecosystem, tt.args.queries...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetIndexes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Connection.GetIndexes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnection_GetDetection(t *testing.T) {
	type fields struct {
		Config *rdb.Config
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
			c := &rdb.Connection{
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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Connection.GetDetection() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnection_GetDataSources(t *testing.T) {
	type fields struct {
		Config *rdb.Config
	}
	tests := []struct {
		name    string
		fields  fields
		want    []datasourceTypes.DataSource
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &rdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close() //nolint:errcheck

			got, err := c.GetDataSources()
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetDataSources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Connection.GetDataSources() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnection_GetDataSource(t *testing.T) {
	type fields struct {
		Config *rdb.Config
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
			c := &rdb.Connection{
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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Connection.GetDataSource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnection_PutDataSource(t *testing.T) {
	type fields struct {
		Config *rdb.Config
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
			c := &rdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if err := c.PutDataSource(tt.args.root); (err != nil) != tt.wantErr {
				t.Errorf("Connection.PutDataSource() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnection_DeleteAll(t *testing.T) {
	type fields struct {
		Config *rdb.Config
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &rdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if err := c.DeleteAll(); (err != nil) != tt.wantErr {
				t.Errorf("Connection.DeleteAll() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnection_Initialize(t *testing.T) {
	type fields struct {
		Config *rdb.Config
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &rdb.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			if err := c.Initialize(); (err != nil) != tt.wantErr {
				t.Errorf("Connection.Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
