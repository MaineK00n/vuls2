package cache_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/cache"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		want *cache.Cache
	}{
		{
			name: "happy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cache.New(); got == nil {
				t.Errorf("New() = %v, want %v", got, "not nil")
			}
		})
	}
}

func TestCache_Close(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "happy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.New()
			c.Close()

			if c.GetAdvisories() != nil || c.GetVulnerabilities() != nil {
				t.Errorf("Cache.Close() did not set maps to nil")
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
			c := cache.New()
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
			if diff := cmp.Diff(tt.want.am, got1); diff != "" {
				t.Errorf("Cache.LoadAdvisory() fist value. (-expected +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.want.ok, got2); diff != "" {
				t.Errorf("Cache.LoadAdvisory() second value. (-expected +got):\n%s", diff)
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
		{
			name: "happy",
			args: args{
				key: "advisory1",
				value: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
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
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.New()
			c.StoreAdvisory(tt.args.key, tt.args.value)

			got, ok := c.LoadAdvisory(tt.args.key)
			if !ok {
				t.Errorf("Cache.LoadAdvisory() ok = false, want true")
			}
			if diff := cmp.Diff(tt.args.value, got); diff != "" {
				t.Errorf("Cache.LoadAdvisory() value. (-expected +got):\n%s", diff)
			}
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
			c := cache.New()
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
			if diff := cmp.Diff(tt.want.vm, got1); diff != "" {
				t.Errorf("Cache.LoadVulnerability() first value. (-expected +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.want.ok, got2); diff != "" {
				t.Errorf("Cache.LoadVulnerability() second value. (-expected +got):\n%s", diff)
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
		{
			name: "happy",
			args: args{
				key: "vulnerability1",
				value: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
					"source1": {
						"root1": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln1",
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
			c := cache.New()
			c.StoreVulnerability(tt.args.key, tt.args.value)

			got, ok := c.LoadVulnerability(tt.args.key)
			if !ok {
				t.Errorf("Cache.LoadVulnerability() ok = false, want true")
			}
			if diff := cmp.Diff(tt.args.value, got); diff != "" {
				t.Errorf("Cache.LoadVulnerability() value. (-expected +got):\n%s", diff)
			}
		})
	}
}
