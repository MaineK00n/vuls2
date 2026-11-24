package flag_test

import (
	"testing"

	utilflag "github.com/MaineK00n/vuls2/pkg/cmd/util/flag"
)

func TestDBType_Set(t *testing.T) {
	tests := []struct {
		name    string
		v       string
		want    utilflag.DBType
		wantErr bool
	}{
		{
			name: "boltdb",
			v:    "boltdb",
			want: utilflag.DBType("boltdb"),
		},
		{
			name:    "redis",
			v:       "redis",
			wantErr: true,
		},
		{
			name:    "sqlite3",
			v:       "sqlite3",
			wantErr: true,
		},
		{
			name:    "mysql",
			v:       "mysql",
			wantErr: true,
		},
		{
			name:    "postgres",
			v:       "postgres",
			wantErr: true,
		},
		{
			name:    "empty",
			v:       "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got utilflag.DBType
			err := got.Set(tt.v)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DBType.Set(%q) error = %v, wantErr %v", tt.v, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("DBType.Set(%q) = %q, want %q", tt.v, got, tt.want)
			}
		})
	}
}
