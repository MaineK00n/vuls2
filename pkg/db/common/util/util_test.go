package util_test

import (
	"reflect"
	"testing"

	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	"github.com/MaineK00n/vuls2/pkg/db/common/util"
)

func TestReplaceRepositories(t *testing.T) {
	type args struct {
		conds []conditionTypes.Condition
		repom map[string]string
	}
	tests := []struct {
		name      string
		args      args
		wantConds []conditionTypes.Condition
		wantRepom map[string]string
		wantErr   bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := util.ReplaceRepositories(tt.args.conds, tt.args.repom); (err != nil) != tt.wantErr {
				t.Errorf("ReplaceRepositories() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(tt.args.conds, tt.wantConds) {
				t.Errorf("ReplaceRepositories() = %v, want %v", tt.args.conds, tt.wantConds)
			}
			if !reflect.DeepEqual(tt.args.repom, tt.wantRepom) {
				t.Errorf("ReplaceRepositories() = %v, want %v", tt.args.repom, tt.wantRepom)
			}
		})
	}
}

func TestCollectPkgName(t *testing.T) {
	type args struct {
		conds []conditionTypes.Condition
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.CollectPkgName(tt.args.conds)
			if (err != nil) != tt.wantErr {
				t.Errorf("CollectPkgName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CollectPkgName() = %v, want %v", got, tt.want)
			}
		})
	}
}
