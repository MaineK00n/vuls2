package util_test

import (
	"reflect"
	"testing"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/common/util"
)

func TestNewCache(t *testing.T) {
	tests := []struct {
		name string
		want *util.Cache
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := util.NewCache(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCache_LoadAdvisory(t *testing.T) {
	type args struct {
		key advisoryContentTypes.AdvisoryID
	}
	type want struct {
		am map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
		ok bool
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "existing key",
			args: args{
				key: "key1",
			},
			want: want{
				am: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
					"source1": {
						"root1": {
							{
								Content: advisoryContentTypes.Content{
									ID: "key1",
								},
							},
						},
					},
				},
				ok: true,
			},
		},
		{
			name: "non-existing key",
			args: args{
				key: "key3",
			},
			want: want{
				am: nil,
				ok: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := util.NewCache()
			c.StoreAdvisory("key1", map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"source1": {
					"root1": {
						{
							Content: advisoryContentTypes.Content{
								ID: "key1",
							},
						},
					},
				},
			})
			c.StoreAdvisory("key2", map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"source1": {
					"root1": {
						{
							Content: advisoryContentTypes.Content{
								ID: "key2",
							},
						},
					},
				},
			})

			got1, got2 := c.LoadAdvisory(tt.args.key)
			if !reflect.DeepEqual(got1, tt.want.am) {
				t.Errorf("cache.LoadAdvisory() got = %v, want %v", got1, tt.want.am)
			}
			if got2 != tt.want.ok {
				t.Errorf("cache.LoadAdvisory() got1 = %v, want %v", got2, tt.want.ok)
			}
		})
	}
}

func TestCache_StoreAdvisory(t *testing.T) {
	type args struct {
		key   advisoryContentTypes.AdvisoryID
		value map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := util.NewCache()
			c.StoreAdvisory(tt.args.key, tt.args.value)
		})
	}
}

func TestCache_LoadVulnerability(t *testing.T) {
	type args struct {
		key vulnerabilityContentTypes.VulnerabilityID
	}
	type want struct {
		vm map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
		ok bool
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "existing key",
			args: args{
				key: "vuln2",
			},
			want: want{
				vm: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
					"source1": {
						"root1": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln2",
								},
							},
						},
					},
				},
				ok: true,
			},
		},
		{
			name: "non-existing key",
			args: args{
				key: "vuln3",
			},
			want: want{
				vm: nil,
				ok: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := util.NewCache()
			c.StoreVulnerability("vuln1", map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"source1": {
					"root1": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln1",
							},
						},
					},
				},
			})
			c.StoreVulnerability("vuln2", map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"source1": {
					"root1": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln2",
							},
						},
					},
				},
			})

			got1, got2 := c.LoadVulnerability(tt.args.key)
			if !reflect.DeepEqual(got1, tt.want.vm) {
				t.Errorf("cache.LoadVulnerability() got = %v, want %v", got1, tt.want.vm)
			}
			if got2 != tt.want.ok {
				t.Errorf("cache.LoadVulnerability() got1 = %v, want %v", got2, tt.want.ok)
			}
		})
	}
}

func TestCache_StoreVulnerability(t *testing.T) {
	type args struct {
		key   vulnerabilityContentTypes.VulnerabilityID
		value map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := util.NewCache()
			c.StoreVulnerability(tt.args.key, tt.args.value)
		})
	}
}
