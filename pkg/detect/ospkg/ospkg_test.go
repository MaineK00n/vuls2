package ospkg_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	kbcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/kbcriterion"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	"github.com/MaineK00n/vuls2/pkg/detect/internal/test"
	"github.com/MaineK00n/vuls2/pkg/detect/ospkg"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
)

func TestDetect(t *testing.T) {
	type args struct {
		sr          scanTypes.ScanResult
		concurrency int
	}
	tests := []struct {
		name    string
		fixture string
		config  session.Config
		args    args
		want    map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection
		wantErr error
	}{
		{
			// GetEcosystem failing must be wrapped and yielded terminally. The
			// input drives the stable unparsable-release branch rather than the
			// unknown-family one: the latter's message embeds upstream's full
			// ecosystem list, which would break on every vuls-data-update bump.
			name:    "unparsable release returns error",
			fixture: "testdata/fixtures/alma-small",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				sr: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeAlpine,
					Release: "3",
				},
				concurrency: 1,
			},
			wantErr: errors.New(`get ecosystem. family: alpine, release: 3: unexpected release format. expected: "<major>.<minor>(.<patch>)", actual: "3"`),
		},
		{
			name:    "routes Microsoft to microsoft.Detect",
			fixture: "testdata/fixtures/microsoft-kb",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				sr: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeMicrosoft,
					Release: "Windows 10 Version 2004 for x64-based Systems",
					MicrosoftKB: scanTypes.MicrosoftKB{
						Unapplied: []string{"5000802"},
					},
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{
				"CVE-2021-1640": {
					Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						"microsoft-cvrf": {
							{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{
										{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{
												{
													Criterion: criterionTypes.Criterion{
														Type: criterionTypes.CriterionTypeKB,
														KB: &kbcTypes.Criterion{
															Product: "Windows 10 Version 2004 for x64-based Systems",
															KBID:    "5000802",
														},
													},
													Accepts: criterionTypes.AcceptQueries{KB: criterionTypes.KB{Unapplied: true}},
												},
											},
										},
									},
								},
								Tag: segmentTypes.DetectionTag("Windows 10 Version 2004 for x64-based Systems"),
							},
						},
					},
				},
				"CVE-2021-26413": {
					Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						"microsoft-cvrf": {
							{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{
										{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{
												{
													Criterion: criterionTypes.Criterion{
														Type: criterionTypes.CriterionTypeKB,
														KB: &kbcTypes.Criterion{
															Product: "Windows 10 Version 2004 for x64-based Systems",
															KBID:    "5001330",
														},
													},
													Accepts: criterionTypes.AcceptQueries{KB: criterionTypes.KB{Unapplied: true}},
												},
											},
										},
									},
								},
								Tag: segmentTypes.DetectionTag("Windows 10 Version 2004 for x64-based Systems"),
							},
						},
					},
				},
			},
		},
		{
			name:    "routes non-Microsoft (alma) to base.Detect",
			fixture: "testdata/fixtures/alma-small",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				sr: scanTypes.ScanResult{
					Family:  "alma",
					Release: "8.9",
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{},
		},
		{
			name:    "empty Microsoft scan result returns empty",
			fixture: "testdata/fixtures/microsoft-kb",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				sr: scanTypes.ScanResult{
					Family: ecosystemTypes.EcosystemTypeMicrosoft,
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(tt.config, tt.fixture); err != nil {
				t.Fatalf("populate db: %v", err)
			}

			s, err := tt.config.New()
			if err != nil {
				t.Fatalf("new session: %v", err)
			}
			if err := s.Storage().Open(); err != nil {
				t.Fatalf("open: %v", err)
			}
			defer s.Storage().Close()
			defer s.Cache().Close()

			got, err := test.CollectDetections(ospkg.Detect(s.Storage(), tt.args.sr, tt.args.concurrency))
			switch {
			case tt.wantErr == nil && err != nil:
				t.Errorf("Detect() unexpected error: %v", err)
			case tt.wantErr != nil && err == nil:
				t.Errorf("Detect() expected error has not occurred")
			case tt.wantErr != nil && err != nil:
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("Detect() error mismatch: want %v, got %v", tt.wantErr, err)
				}
			default:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
