package build

import (
	"log/slog"
	"testing"
)

func TestDBLogAttr(t *testing.T) {
	tests := []struct {
		name   string
		dbtype string
		dbpath string
		want   slog.Attr
	}{
		{
			name:   "boltdb logs the path",
			dbtype: "boltdb",
			dbpath: "/var/cache/vuls/vuls.db",
			want:   slog.String("dbpath", "/var/cache/vuls/vuls.db"),
		},
		{
			name:   "postgres does not log the connection string",
			dbtype: "postgres",
			dbpath: "postgres://vuls:secret@db.example.com:5432/vuls",
			want:   slog.String("dbtype", "postgres"),
		},
		{
			name:   "redis does not log the connection string",
			dbtype: "redis",
			dbpath: "redis://:secret@127.0.0.1:6379/0",
			want:   slog.String("dbtype", "redis"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dbLogAttr(tt.dbtype, tt.dbpath); !got.Equal(tt.want) {
				t.Errorf("dbLogAttr() = %v, want %v", got, tt.want)
			}
		})
	}
}
