package redis_test

import (
	"reflect"
	"testing"

	"github.com/redis/rueidis"

	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/common/redis"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

func TestConnection_Open(t *testing.T) {
	type fields struct {
		Config *rueidis.ClientOption
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &redis.Connection{
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
		Config *rueidis.ClientOption
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &redis.Connection{
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
		Config *rueidis.ClientOption
	}
	tests := []struct {
		name    string
		fields  fields
		want    *dbTypes.Metadata
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &redis.Connection{
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
		Config *rueidis.ClientOption
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
			c := &redis.Connection{
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

func TestConnection_GetVulnerabilityDetections(t *testing.T) {
	type fields struct {
		Config *rueidis.ClientOption
	}
	type args struct {
		searchType dbTypes.SearchDetectionType
		queries    []string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantResCh <-chan dbTypes.VulnerabilityDataDetection
		wantErrCh <-chan error
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &redis.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			gotResCh, gotErrCh := c.GetVulnerabilityDetections(tt.args.searchType, tt.args.queries...)
			if !reflect.DeepEqual(gotResCh, tt.wantResCh) {
				t.Errorf("Connection.GetVulnerabilityDetections() got = %v, want %v", gotResCh, tt.wantResCh)
			}
			if !reflect.DeepEqual(gotErrCh, tt.wantErrCh) {
				t.Errorf("Connection.GetVulnerabilityDetections() got1 = %v, want %v", gotErrCh, tt.wantErrCh)
			}
		})
	}
}

func TestConnection_GetVulnerabilityData(t *testing.T) {
	type fields struct {
		Config *rueidis.ClientOption
	}
	type args struct {
		searchType dbTypes.SearchDataType
		id         string
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
			c := &redis.Connection{
				Config: tt.fields.Config,
			}
			if err := c.Open(); err != nil {
				t.Fatalf("open db. error = %v", err)
			}
			defer c.Close()

			got, err := c.GetVulnerabilityData(tt.args.searchType, tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Connection.GetVulnerabilityData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Connection.GetVulnerabilityData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnection_PutVulnerabilityData(t *testing.T) {
	type fields struct {
		Config *rueidis.ClientOption
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
			c := &redis.Connection{
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

func TestConnection_GetDataSource(t *testing.T) {
	type fields struct {
		Config *rueidis.ClientOption
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
			c := &redis.Connection{
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
		Config *rueidis.ClientOption
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
			c := &redis.Connection{
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
		Config *rueidis.ClientOption
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &redis.Connection{
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
		Config *rueidis.ClientOption
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &redis.Connection{
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
