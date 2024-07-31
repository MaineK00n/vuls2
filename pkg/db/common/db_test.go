package common_test

import (
	"reflect"
	"testing"

	"github.com/MaineK00n/vuls2/pkg/db/common"
)

func TestConfig_New(t *testing.T) {
	type fields struct {
		Type  string
		Path  string
		Debug bool
	}
	tests := []struct {
		name    string
		fields  fields
		want    common.DB
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &common.Config{
				Type:  tt.fields.Type,
				Path:  tt.fields.Path,
				Debug: tt.fields.Debug,
			}
			got, err := c.New()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Config.New() = %v, want %v", got, tt.want)
			}
		})
	}
}
