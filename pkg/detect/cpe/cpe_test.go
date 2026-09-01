package cpe_test

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
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	"github.com/MaineK00n/vuls2/pkg/detect/cpe"
	"github.com/MaineK00n/vuls2/pkg/detect/internal/test"
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
			name:    "no cpe in scan result",
			fixture: "testdata/fixtures/nvd-cpe",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				sr:          scanTypes.ScanResult{},
				concurrency: 1,
			},
			// An empty CPE list yields nothing; collecting the empty
			// stream produces an empty (non-nil) map.
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{},
		},
		{
			// A malformed scanned CPE fails UnbindFS inside the lazy body and
			// is yielded as a terminal error.
			name:    "malformed cpe yields an error",
			fixture: "testdata/fixtures/nvd-cpe",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				sr:          scanTypes.ScanResult{CPE: []string{"not-a-cpe"}},
				concurrency: 1,
			},
			wantErr: errors.New(`unbind "not-a-cpe" to WFN: Error: Formatted String must start with "cpe:2.3". Given: not-a-cpe: Parse error`),
		},
		{
			// Same vendor:product but part "a" instead of "o" must not match the
			// indexed key "o:google:android" — guards the part:vendor:product key.
			name:    "miss: part differs",
			fixture: "testdata/fixtures/nvd-cpe",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				sr:          scanTypes.ScanResult{CPE: []string{"cpe:2.3:a:google:android:16.0:*:*:*:*:*:*:*"}},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{},
		},
		{
			name:    "hit: part:vendor:product matches",
			fixture: "testdata/fixtures/nvd-cpe",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				sr:          scanTypes.ScanResult{CPE: []string{"cpe:2.3:o:google:android:16.0:*:*:*:*:*:*:*"}},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{
				dataTypes.RootID("CVE-2024-0028"): {
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						sourceTypes.NVDFeedCVEv2: {
							{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{
										{
											Operator: criteriaTypes.CriteriaOperatorTypeOR,
											Criterias: []criteriaTypes.FilteredCriteria{
												{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeOR,
															Criterions: []criterionTypes.FilteredCriterion{
																{
																	Criterion: criterionTypes.Criterion{
																		Type: criterionTypes.CriterionTypeCPE,
																		CPE: &ccTypes.Criterion{
																			Vulnerable: true,
																			FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassUnknown},
																			CPE:        "cpe:2.3:o:google:android:16.0:*:*:*:*:*:*:*",
																		},
																	},
																	Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}, VersionUnconfirmed: []int{}}},
																},
															},
														},
													},
												},
											},
										},
									},
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
			if err := test.PopulateDB(tt.config, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			s, err := tt.config.New()
			if err != nil {
				t.Fatalf("new session. error = %v", err)
			}

			if err := s.Storage().Open(); err != nil {
				t.Fatalf("open db connection. error = %v", err)
			}
			defer s.Storage().Close()
			defer s.Cache().Close()

			got, err := test.CollectDetections(cpe.Detect(s.Storage(), tt.args.sr, tt.args.concurrency))
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
					t.Errorf("Detect() (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
