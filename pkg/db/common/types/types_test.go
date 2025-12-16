package types_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

func TestNewFilterContentType(t *testing.T) {
	tests := []struct {
		name    string
		str     string
		want    dbTypes.FilterContentType
		wantErr bool
	}{
		{
			name:    "advisories",
			str:     "advisories",
			want:    dbTypes.FilterContentTypeAdvisories,
			wantErr: false,
		},
		{
			name:    "vulnerabilities",
			str:     "vulnerabilities",
			want:    dbTypes.FilterContentTypeVulnerabilities,
			wantErr: false,
		},
		{
			name:    "detections",
			str:     "detections",
			want:    dbTypes.FilterContentTypeDetections,
			wantErr: false,
		},
		{
			name:    "datasources",
			str:     "datasources",
			want:    dbTypes.FilterContentTypeDataSources,
			wantErr: false,
		},
		{
			name:    "invalid content type",
			str:     "invalid",
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := dbTypes.NewFilterContentType(tt.str)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("NewFilterContentType() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Error("NewFilterContentType() succeeded unexpectedly")
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("NewFilterContentType(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestFilter_ApplyShallowly(t *testing.T) {
	type fields struct {
		Contents   []dbTypes.FilterContentType
		RootIDs    []dataTypes.RootID
		Ecosystems []ecosystemTypes.Ecosystem
	}
	type args struct {
		vd dbTypes.VulnerabilityData
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   dbTypes.VulnerabilityData
	}{
		{
			name: "no filter",
			fields: fields{
				Contents: dbTypes.AllFilterContentTypes(),
			},
			args: args{
				vd: dbTypes.VulnerabilityData{
					Advisories: []dbTypes.VulnerabilityDataAdvisory{
						{
							ID: "adv-1",
						},
					},
					Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
						{
							ID: "vuln-1",
						},
					},
					Detections: []dbTypes.VulnerabilityDataDetection{
						{
							Ecosystem: "ubuntu:24.04",
						},
					},
					DataSources: []datasource.DataSource{
						{
							ID: "source-1",
						},
					},
				},
			},
			want: dbTypes.VulnerabilityData{
				Advisories: []dbTypes.VulnerabilityDataAdvisory{
					{
						ID: "adv-1",
					},
				},
				Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
					{
						ID: "vuln-1",
					},
				},
				Detections: []dbTypes.VulnerabilityDataDetection{
					{
						Ecosystem: "ubuntu:24.04",
					},
				},
				DataSources: []datasource.DataSource{
					{
						ID: "source-1",
					},
				},
			},
		},
		{
			name: "no advisories",
			fields: fields{
				Contents: []dbTypes.FilterContentType{
					dbTypes.FilterContentTypeVulnerabilities,
					dbTypes.FilterContentTypeDetections,
					dbTypes.FilterContentTypeDataSources,
				},
			},
			args: args{
				vd: dbTypes.VulnerabilityData{
					Advisories: []dbTypes.VulnerabilityDataAdvisory{
						{
							ID: "adv-1",
						},
					},
					Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
						{
							ID: "vuln-1",
						},
					},
					Detections: []dbTypes.VulnerabilityDataDetection{
						{
							Ecosystem: "ubuntu:24.04",
						},
					},
					DataSources: []datasource.DataSource{
						{
							ID: "source-1",
						},
					},
				},
			},
			want: dbTypes.VulnerabilityData{
				Advisories: nil,
				Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
					{
						ID: "vuln-1",
					},
				},
				Detections: []dbTypes.VulnerabilityDataDetection{
					{
						Ecosystem: "ubuntu:24.04",
					},
				},
				DataSources: []datasource.DataSource{
					{
						ID: "source-1",
					},
				},
			},
		},
		{
			name: "no vulnerabilities",
			fields: fields{
				Contents: []dbTypes.FilterContentType{
					dbTypes.FilterContentTypeAdvisories,
					dbTypes.FilterContentTypeDetections,
					dbTypes.FilterContentTypeDataSources,
				},
			},
			args: args{
				vd: dbTypes.VulnerabilityData{
					Advisories: []dbTypes.VulnerabilityDataAdvisory{
						{
							ID: "adv-1",
						},
					},
					Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
						{
							ID: "vuln-1",
						},
					},
					Detections: []dbTypes.VulnerabilityDataDetection{
						{
							Ecosystem: "ubuntu:24.04",
						},
					},
					DataSources: []datasource.DataSource{
						{
							ID: "source-1",
						},
					},
				},
			},
			want: dbTypes.VulnerabilityData{
				Advisories: []dbTypes.VulnerabilityDataAdvisory{
					{
						ID: "adv-1",
					},
				},
				Vulnerabilities: nil,
				Detections: []dbTypes.VulnerabilityDataDetection{
					{
						Ecosystem: "ubuntu:24.04",
					},
				},
				DataSources: []datasource.DataSource{
					{
						ID: "source-1",
					},
				},
			},
		},
		{
			name: "no detections",
			fields: fields{
				Contents: []dbTypes.FilterContentType{
					dbTypes.FilterContentTypeAdvisories,
					dbTypes.FilterContentTypeVulnerabilities,
					dbTypes.FilterContentTypeDataSources,
				},
			},
			args: args{
				vd: dbTypes.VulnerabilityData{
					Advisories: []dbTypes.VulnerabilityDataAdvisory{
						{
							ID: "adv-1",
						},
					},
					Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
						{
							ID: "vuln-1",
						},
					},
					Detections: []dbTypes.VulnerabilityDataDetection{
						{
							Ecosystem: "ubuntu:24.04",
						},
					},
					DataSources: []datasource.DataSource{
						{
							ID: "source-1",
						},
					},
				},
			},
			want: dbTypes.VulnerabilityData{
				Advisories: []dbTypes.VulnerabilityDataAdvisory{
					{
						ID: "adv-1",
					},
				},
				Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
					{
						ID: "vuln-1",
					},
				},
				Detections: nil,
				DataSources: []datasource.DataSource{
					{
						ID: "source-1",
					},
				},
			},
		},
		{
			name: "no datasources",
			fields: fields{
				Contents: []dbTypes.FilterContentType{
					dbTypes.FilterContentTypeAdvisories,
					dbTypes.FilterContentTypeVulnerabilities,
					dbTypes.FilterContentTypeDetections,
				},
			},
			args: args{
				vd: dbTypes.VulnerabilityData{
					Advisories: []dbTypes.VulnerabilityDataAdvisory{
						{
							ID: "adv-1",
						},
					},
					Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
						{
							ID: "vuln-1",
						},
					},
					Detections: []dbTypes.VulnerabilityDataDetection{
						{
							Ecosystem: "ubuntu:24.04",
						},
					},
					DataSources: []datasource.DataSource{
						{
							ID: "source-1",
						},
					},
				},
			},
			want: dbTypes.VulnerabilityData{
				Advisories: []dbTypes.VulnerabilityDataAdvisory{
					{
						ID: "adv-1",
					},
				},
				Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
					{
						ID: "vuln-1",
					},
				},
				Detections: []dbTypes.VulnerabilityDataDetection{
					{
						Ecosystem: "ubuntu:24.04",
					},
				},
				DataSources: nil,
			},
		},
		{
			name: "detections only",
			fields: fields{
				Contents: []dbTypes.FilterContentType{
					dbTypes.FilterContentTypeDetections,
				},
			},
			args: args{
				vd: dbTypes.VulnerabilityData{
					Advisories: []dbTypes.VulnerabilityDataAdvisory{
						{
							ID: "adv-1",
						},
					},
					Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
						{
							ID: "vuln-1",
						},
					},
					Detections: []dbTypes.VulnerabilityDataDetection{
						{
							Ecosystem: "ubuntu:24.04",
						},
					},
					DataSources: []datasource.DataSource{
						{
							ID: "source-1",
						},
					},
				},
			},
			want: dbTypes.VulnerabilityData{
				Advisories:      nil,
				Vulnerabilities: nil,
				Detections: []dbTypes.VulnerabilityDataDetection{
					{
						Ecosystem: "ubuntu:24.04",
					},
				},
				DataSources: nil,
			},
		},
		{
			name: "advisories and vulnerabilities only",
			fields: fields{
				Contents: []dbTypes.FilterContentType{
					dbTypes.FilterContentTypeAdvisories,
					dbTypes.FilterContentTypeVulnerabilities,
				},
			},
			args: args{
				vd: dbTypes.VulnerabilityData{
					Advisories: []dbTypes.VulnerabilityDataAdvisory{
						{
							ID: "adv-1",
						},
					},
					Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
						{
							ID: "vuln-1",
						},
					},
					Detections: []dbTypes.VulnerabilityDataDetection{
						{
							Ecosystem: "ubuntu:24.04",
						},
					},
					DataSources: []datasource.DataSource{
						{
							ID: "source-1",
						},
					},
				},
			},
			want: dbTypes.VulnerabilityData{
				Advisories: []dbTypes.VulnerabilityDataAdvisory{
					{
						ID: "adv-1",
					},
				},
				Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
					{
						ID: "vuln-1",
					},
				},
				Detections:  nil,
				DataSources: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dbTypes.Filter{
				Contents:   tt.fields.Contents,
				RootIDs:    tt.fields.RootIDs,
				Ecosystems: tt.fields.Ecosystems,
			}

			got := f.ApplyShallowly(tt.args.vd)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Fetch(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestFilter_ApplyToAdvisories(t *testing.T) {
	type fields struct {
		Ecosystems []ecosystemTypes.Ecosystem
		RootIDs    []dataTypes.RootID
	}
	type args struct {
		asmm map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
	}{
		{
			name: "no filter",
			args: args{
				asmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
					"source1": {
						"root1": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"source1": {
					"root1": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
			},
		},
		{
			name: "filter by ecosystem",
			fields: fields{
				Ecosystems: []ecosystemTypes.Ecosystem{"ubuntu:24.04"},
			},
			args: args{
				asmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
					"source1": {
						"root1": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
					"source2": {
						"root3": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-3",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root4": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-4",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
						},
						"root5": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-5-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-5-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"source1": {
					"root1": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
				"source2": {
					"root3": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-3",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
					"root5": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-5-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
			},
		},
		{
			name: "filter by two ecosystem",
			fields: fields{
				Ecosystems: []ecosystemTypes.Ecosystem{"oracle:9", "ubuntu:24.04"},
			},
			args: args{
				asmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
					"source1": {
						"root1": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
					"source2": {
						"root3": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-3",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root4": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-4",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
						},
						"root5": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-5-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-5-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"source1": {
					"root1": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
					"root2": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-2",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "oracle:9"},
							},
						},
					},
				},
				"source2": {
					"root3": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-3",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
					"root5": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-5-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-5-2",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "oracle:9"},
							},
						},
					},
				},
			},
		},
		{
			name: "filter by root ID",
			fields: fields{
				RootIDs: []dataTypes.RootID{"root1"},
			},
			args: args{
				asmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
					"source1": {
						"root1": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"source1": {
					"root1": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
			},
		},
		{
			name: "filter by two root IDs",
			fields: fields{
				RootIDs: []dataTypes.RootID{"root1", "root3"},
			},
			args: args{
				asmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
					"source1": {
						"root1": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
					"source2": {
						"root3": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-3",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root4": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-4",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
						},
						"root5": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-5-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-5-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"source1": {
					"root1": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
				"source2": {
					"root3": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-3",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:22.04"},
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
			},
		},
		{
			name: "filter by ecosystem and root ID",
			fields: fields{
				RootIDs:    []dataTypes.RootID{"root1"},
				Ecosystems: []ecosystemTypes.Ecosystem{"ubuntu:24.04"},
			},
			args: args{
				asmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
					"source1": {
						"root1": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
					"source2": {
						"root3": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-3",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root4": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-4",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
						},
						"root5": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-5-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-5-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"source1": {
					"root1": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
			},
		},
		{
			name: "filter by ecosystem and root ID results in no data",
			fields: fields{
				RootIDs:    []dataTypes.RootID{"root1"},
				Ecosystems: []ecosystemTypes.Ecosystem{"oracle:9"},
			},
			args: args{
				asmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
					"source1": {
						"root1": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
					"source2": {
						"root3": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-3",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root4": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-4",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
						},
						"root5": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-5-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-5-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{},
		},
		{
			name: "filter by two ecosystems and two root IDs",
			fields: fields{
				RootIDs:    []dataTypes.RootID{"root1", "root5"},
				Ecosystems: []ecosystemTypes.Ecosystem{"ubuntu:24.04", "oracle:9"},
			},
			args: args{
				asmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
					"source1": {
						"root1": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
					"source2": {
						"root3": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-3",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root4": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-4",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
						},
						"root5": {
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-5-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
							{
								Content: advisoryContentTypes.Content{
									ID: "adv-5-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
				"source1": {
					"root1": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
				"source2": {
					"root5": {
						{
							Content: advisoryContentTypes.Content{
								ID: "adv-5-2",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "oracle:9"},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dbTypes.Filter{
				Ecosystems: tt.fields.Ecosystems,
				RootIDs:    tt.fields.RootIDs,
			}

			got := f.ApplyToAdvisories(tt.args.asmm)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Filter.ApplyToAdvisories(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestFilter_ApplyToVulnerabilities(t *testing.T) {
	type fields struct {
		Ecosystems []ecosystemTypes.Ecosystem
		RootIDs    []dataTypes.RootID
	}
	type args struct {
		vsmm map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
	}{
		{
			name: "no filter",
			args: args{
				vsmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
					"source1": {
						"root1": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"source1": {
					"root1": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
			},
		},
		{
			name: "filter by ecosystem",
			fields: fields{
				Ecosystems: []ecosystemTypes.Ecosystem{"ubuntu:24.04"},
			},
			args: args{
				vsmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
					"source1": {
						"root1": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
					"source2": {
						"root3": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-3",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root4": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-4",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
						},
						"root5": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-5-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-5-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"source1": {
					"root1": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
				"source2": {
					"root3": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-3",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
					"root5": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-5-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
			},
		},
		{
			name: "filter by two ecosystem",
			fields: fields{
				Ecosystems: []ecosystemTypes.Ecosystem{"oracle:9", "ubuntu:24.04"},
			},
			args: args{
				vsmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
					"source1": {
						"root1": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
					"source2": {
						"root3": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-3",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root4": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-4",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
						},
						"root5": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-5-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-5-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"source1": {
					"root1": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
					"root2": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-2",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "oracle:9"},
							},
						},
					},
				},
				"source2": {
					"root3": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-3",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
					"root5": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-5-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-5-2",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "oracle:9"},
							},
						},
					},
				},
			},
		},
		{
			name: "filter by root ID",
			fields: fields{
				RootIDs: []dataTypes.RootID{"root1"},
			},
			args: args{
				vsmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
					"source1": {
						"root1": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"source1": {
					"root1": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
			},
		},
		{
			name: "filter by two root IDs",
			fields: fields{
				RootIDs: []dataTypes.RootID{"root1", "root3"},
			},
			args: args{
				vsmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
					"source1": {
						"root1": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
					"source2": {
						"root3": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-3",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root4": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-4",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
						},
						"root5": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-5-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-5-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"source1": {
					"root1": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
				"source2": {
					"root3": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-3",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:22.04"},
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
			},
		},
		{
			name: "filter by ecosystem and root ID",
			fields: fields{
				RootIDs:    []dataTypes.RootID{"root1"},
				Ecosystems: []ecosystemTypes.Ecosystem{"ubuntu:24.04"},
			},
			args: args{
				vsmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
					"source1": {
						"root1": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
					"source2": {
						"root3": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-3",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root4": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-4",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
						},
						"root5": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-5-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-5-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"source1": {
					"root1": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
			},
		},
		{
			name: "filter by ecosystem and root ID results in no data",
			fields: fields{
				RootIDs:    []dataTypes.RootID{"root1"},
				Ecosystems: []ecosystemTypes.Ecosystem{"oracle:9"},
			},
			args: args{
				vsmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
					"source1": {
						"root1": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
					"source2": {
						"root3": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-3",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root4": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-4",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
						},
						"root5": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-5-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-5-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{},
		},
		{
			name: "filter by two ecosystems and two root IDs",
			fields: fields{
				RootIDs:    []dataTypes.RootID{"root1", "root5"},
				Ecosystems: []ecosystemTypes.Ecosystem{"ubuntu:24.04", "oracle:9"},
			},
			args: args{
				vsmm: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
					"source1": {
						"root1": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root2": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
					"source2": {
						"root3": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-3",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:22.04"},
									{Ecosystem: "ubuntu:24.04"},
								},
							},
						},
						"root4": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-4",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
						},
						"root5": {
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-5-1",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ubuntu:20.04"},
									{Ecosystem: "ubuntu:22.04"},
								},
							},
							{
								Content: vulnerabilityContentTypes.Content{
									ID: "vuln-5-2",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "oracle:9"},
								},
							},
						},
					},
				},
			},
			want: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
				"source1": {
					"root1": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-1",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ubuntu:24.04"},
							},
						},
					},
				},
				"source2": {
					"root5": {
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vuln-5-2",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "oracle:9"},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dbTypes.Filter{
				Ecosystems: tt.fields.Ecosystems,
				RootIDs:    tt.fields.RootIDs,
			}

			got := f.ApplyToVulnerabilities(tt.args.vsmm)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Fetch(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestFilter_ApplyToEcosystems(t *testing.T) {
	type fields struct {
		Ecosystems []ecosystemTypes.Ecosystem
		RootIDs    []dataTypes.RootID
	}
	type args struct {
		es []ecosystemTypes.Ecosystem
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []ecosystemTypes.Ecosystem
	}{
		{
			name: "no filter",
			args: args{
				es: []ecosystemTypes.Ecosystem{
					"ubuntu:24.04",
					"oracle:9",
				},
			},
			want: []ecosystemTypes.Ecosystem{
				"ubuntu:24.04",
				"oracle:9",
			},
		},
		{
			name: "filter by ecosystem",
			fields: fields{
				Ecosystems: []ecosystemTypes.Ecosystem{"ubuntu:24.04"},
			},
			args: args{
				es: []ecosystemTypes.Ecosystem{
					"ubuntu:24.04",
					"oracle:9",
					"ubuntu:22.04",
				},
			},
			want: []ecosystemTypes.Ecosystem{
				"ubuntu:24.04",
			},
		},
		{
			name: "filter by two ecosystems",
			fields: fields{
				Ecosystems: []ecosystemTypes.Ecosystem{"oracle:9", "ubuntu:24.04"},
			},
			args: args{
				es: []ecosystemTypes.Ecosystem{
					"ubuntu:24.04",
					"oracle:9",
					"ubuntu:22.04",
				},
			},
			want: []ecosystemTypes.Ecosystem{
				"ubuntu:24.04",
				"oracle:9",
			},
		},
		{
			name: "filter by ecosystem results in no data",
			fields: fields{
				Ecosystems: []ecosystemTypes.Ecosystem{"debian:12"},
			},
			args: args{
				es: []ecosystemTypes.Ecosystem{
					"ubuntu:24.04",
					"oracle:9",
					"ubuntu:22.04",
				},
			},
			want: []ecosystemTypes.Ecosystem{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dbTypes.Filter{
				Ecosystems: tt.fields.Ecosystems,
				RootIDs:    tt.fields.RootIDs,
			}

			got := f.ApplyToEcosystems(tt.args.es)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Fetch(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestFilter_ExcludesRootId(t *testing.T) {
	type fields struct {
		rootIDs []dataTypes.RootID
	}
	tests := []struct {
		name   string
		fields fields
		rootID dataTypes.RootID
		want   bool
	}{
		{
			name:   "no filter",
			rootID: "root-1",
			want:   false,
		},
		{
			name: "one root id, matches",
			fields: fields{
				rootIDs: []dataTypes.RootID{"root-1"},
			},
			rootID: "root-1",
			want:   false,
		},
		{
			name: "one root id, not matches",
			fields: fields{
				rootIDs: []dataTypes.RootID{"root-X"},
			},
			rootID: "root-1",
			want:   true,
		},
		{
			name: "two root ids, matches",
			fields: fields{
				rootIDs: []dataTypes.RootID{"root-1", "root-2"},
			},
			rootID: "root-1",
			want:   false,
		},
		{
			name: "two root ids, not matches",
			fields: fields{
				rootIDs: []dataTypes.RootID{"root-X", "root-Y"},
			},
			rootID: "root-1",
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dbTypes.Filter{
				RootIDs: tt.fields.rootIDs,
			}
			got := f.ExcludesRootId(tt.rootID)
			if got != tt.want {
				t.Errorf("ExcludesRootId() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilter_ExcludesEcosystem(t *testing.T) {
	type fields struct {
		ecosystems []ecosystemTypes.Ecosystem
	}
	tests := []struct {
		name      string
		fields    fields
		ecosystem ecosystemTypes.Ecosystem
		want      bool
	}{
		{
			name:      "no filter",
			ecosystem: "ubuntu:24.04",
			want:      false,
		},
		{
			name: "one ecosystem, matches",
			fields: fields{
				ecosystems: []ecosystemTypes.Ecosystem{"ubuntu:24.04"},
			},
			ecosystem: "ubuntu:24.04",
			want:      false,
		},
		{
			name: "one ecosystem, not matches",
			fields: fields{
				ecosystems: []ecosystemTypes.Ecosystem{"oracle:9"},
			},
			ecosystem: "ubuntu:24.04",
			want:      true,
		},
		{
			name: "two ecosystems, matches",
			fields: fields{
				ecosystems: []ecosystemTypes.Ecosystem{"ubuntu:24.04", "oracle:9"},
			},
			ecosystem: "ubuntu:24.04",
			want:      false,
		},
		{
			name: "two ecosystems, not matches",
			fields: fields{
				ecosystems: []ecosystemTypes.Ecosystem{"debian:12", "oracle:9"},
			},
			ecosystem: "ubuntu:24.04",
			want:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := dbTypes.Filter{
				Ecosystems: tt.fields.ecosystems,
			}
			got := f.ExcludesEcosystem(tt.ecosystem)
			if got != tt.want {
				t.Errorf("ExcludesEcosystem() = %v, want %v", got, tt.want)
			}
		})
	}
}
