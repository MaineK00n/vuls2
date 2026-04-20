package db_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"

	db "github.com/MaineK00n/vuls2/pkg/db/diff/db"
	"github.com/MaineK00n/vuls2/pkg/db/session"
)

// populateDB creates a BoltDB at dbPath populated from fixture directories.
func populateDB(dbPath string, fixtureDirs ...string) error {
	c := session.Config{
		Type:    "boltdb",
		Path:    dbPath,
		Options: session.StorageOptions{BoltDB: bolt.DefaultOptions},
	}
	s, err := c.New()
	if err != nil {
		return errors.Wrap(err, "session.New")
	}
	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "storage.Open")
	}
	defer s.Storage().Close()
	if err := s.Storage().Initialize(); err != nil {
		return errors.Wrap(err, "storage.Initialize")
	}
	for _, fixtureDir := range fixtureDirs {
		entries, err := os.ReadDir(fixtureDir)
		if err != nil {
			return errors.Wrapf(err, "ReadDir(%s)", fixtureDir)
		}
		for _, e := range entries {
			if err := s.Storage().Put(filepath.Join(fixtureDir, e.Name())); err != nil {
				return errors.Wrapf(err, "storage.Put(%s)", e.Name())
			}
		}
	}
	return nil
}

func TestGetEcosystems(t *testing.T) {
	type args struct {
		fixture string
	}
	tests := []struct {
		name string
		args args
		want []ecosystemTypes.Ecosystem
	}{
		{
			name: "alma errata",
			args: args{
				fixture: "testdata/fixtures/baseline",
			},
			want: []ecosystemTypes.Ecosystem{"alma:8"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "vuls.db")
			if err := populateDB(dbPath, tt.args.fixture); err != nil {
				t.Fatal(err)
			}

			bdb, err := bolt.Open(dbPath, 0400, &bolt.Options{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer bdb.Close()

			got, err := db.GetEcosystems(bdb)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("GetEcosystems() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDiffEcosystem(t *testing.T) {
	type args struct {
		baselineFixture string
		targetFixture   string
		ecosystem       ecosystemTypes.Ecosystem
	}
	tests := []struct {
		name string
		args args
		want db.EcosystemDiff
	}{
		{
			name: "no change",
			args: args{
				baselineFixture: "testdata/fixtures/baseline",
				targetFixture:   "testdata/fixtures/target-same",
				ecosystem:       "alma:8",
			},
			want: db.EcosystemDiff{
				Ecosystem:          "alma:8",
				BaselineKeys:       1,
				TargetKeys:         1,
				BaselineCriterions: 6,
				TargetCriterions:   6,
				MatchedCriterions:  6,
				Pass:               true,
			},
		},
		{
			name: "added and removed",
			args: args{
				baselineFixture: "testdata/fixtures/baseline",
				targetFixture:   "testdata/fixtures/target-replaced",
				ecosystem:       "alma:8",
			},
			want: db.EcosystemDiff{
				Ecosystem:           "alma:8",
				BaselineKeys:        1,
				TargetKeys:          1,
				Added:               []string{"ALSA-2019:3708"},
				Removed:             []string{"ALSA-2024:0113"},
				BaselineCriterions:  6,
				TargetCriterions:    6,
				DetectionChangeRate: 200,
			},
		},
		{
			name: "changed",
			args: args{
				baselineFixture: "testdata/fixtures/baseline",
				targetFixture:   "testdata/fixtures/target-changed",
				ecosystem:       "alma:8",
			},
			want: db.EcosystemDiff{
				Ecosystem:           "alma:8",
				BaselineKeys:        1,
				TargetKeys:          1,
				Changed:             []string{"ALSA-2024:0113"},
				BaselineCriterions:  6,
				TargetCriterions:    6,
				MatchedCriterions:   5,
				DetectionChangeRate: float64(6-5+6-5) / float64(6) * 100,
			},
		},
		{
			name: "target missing ecosystem",
			args: args{
				baselineFixture: "testdata/fixtures/baseline",
				targetFixture:   "", // empty; set to t.TempDir() in run loop
				ecosystem:       "alma:8",
			},
			want: db.EcosystemDiff{
				Ecosystem:           "alma:8",
				BaselineKeys:        1,
				Removed:             []string{"ALSA-2024:0113"},
				BaselineCriterions:  6,
				DetectionChangeRate: 100,
			},
		},
		{
			name: "target added key",
			args: args{
				baselineFixture: "testdata/fixtures/baseline",
				targetFixture:   "testdata/fixtures/target-added",
				ecosystem:       "alma:8",
			},
			want: db.EcosystemDiff{
				Ecosystem:           "alma:8",
				BaselineKeys:        1,
				TargetKeys:          2,
				Added:               []string{"ALSA-2019:3708"},
				BaselineCriterions:  6,
				TargetCriterions:    12,
				MatchedCriterions:   6,
				DetectionChangeRate: 100,
			},
		},
		{
			name: "criterion change",
			args: args{
				baselineFixture: "testdata/fixtures/change-baseline",
				targetFixture:   "testdata/fixtures/change-target",
				ecosystem:       "test:change",
			},
			want: db.EcosystemDiff{
				Ecosystem:           "test:change",
				BaselineKeys:        2,
				TargetKeys:          2,
				Changed:             []string{"ROOT-0001", "ROOT-0002"},
				BaselineCriterions:  6,
				TargetCriterions:    2,
				MatchedCriterions:   0,
				DetectionChangeRate: float64(6-0+2-0) / float64(6) * 100,
			},
		},
		{
			name: "kb no change",
			args: args{
				baselineFixture: "testdata/fixtures/kb-baseline",
				targetFixture:   "testdata/fixtures/kb-target-same",
				ecosystem:       "microsoft",
			},
			want: db.EcosystemDiff{
				Ecosystem:      "microsoft",
				BaselineKBKeys: 2,
				TargetKBKeys:   2,
				BaselineKBs:    2,
				TargetKBs:      2,
				MatchedKBs:     2,
				Pass:           true,
			},
		},
		{
			name: "kb added",
			args: args{
				baselineFixture: "testdata/fixtures/kb-baseline",
				targetFixture:   "testdata/fixtures/kb-target-added",
				ecosystem:       "microsoft",
			},
			want: db.EcosystemDiff{
				Ecosystem:      "microsoft",
				BaselineKBKeys: 2,
				TargetKBKeys:   3,
				AddedKBs:       []string{"KB5001222"},
				BaselineKBs:    2,
				TargetKBs:      3,
				MatchedKBs:     2,
				KBChangeRate:   50,
			},
		},
		{
			name: "kb changed",
			args: args{
				baselineFixture: "testdata/fixtures/kb-baseline",
				targetFixture:   "testdata/fixtures/kb-target-changed",
				ecosystem:       "microsoft",
			},
			want: db.EcosystemDiff{
				Ecosystem:      "microsoft",
				BaselineKBKeys: 2,
				TargetKBKeys:   2,
				ChangedKBs:     []string{"KB5001111"},
				BaselineKBs:    2,
				TargetKBs:      2,
				MatchedKBs:     1,
				KBChangeRate:   100,
			},
		},
		{
			name: "target missing kb ecosystem",
			args: args{
				baselineFixture: "testdata/fixtures/kb-baseline",
				targetFixture:   "", // empty; set to t.TempDir() in run loop
				ecosystem:       "microsoft",
			},
			want: db.EcosystemDiff{
				Ecosystem:      "microsoft",
				BaselineKBKeys: 2,
				RemovedKBs:     []string{"KB5001000", "KB5001111"},
				BaselineKBs:    2,
				KBChangeRate:   100,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baselineFixture := tt.args.baselineFixture
			if baselineFixture == "" {
				baselineFixture = t.TempDir()
			}
			baselinePath := filepath.Join(t.TempDir(), "vuls.db")
			if err := populateDB(baselinePath, baselineFixture); err != nil {
				t.Fatal(err)
			}
			targetFixture := tt.args.targetFixture
			if targetFixture == "" {
				targetFixture = t.TempDir()
			}
			targetPath := filepath.Join(t.TempDir(), "vuls.db")
			if err := populateDB(targetPath, targetFixture); err != nil {
				t.Fatal(err)
			}

			bdb, err := bolt.Open(baselinePath, 0400, &bolt.Options{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer bdb.Close()

			tdb, err := bolt.Open(targetPath, 0400, &bolt.Options{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer tdb.Close()

			got, err := db.DiffEcosystem(bdb, tdb, tt.args.ecosystem, 0)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("DiffEcosystem() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDiffBoltDB(t *testing.T) {
	type args struct {
		baselineFixtures    []string
		targetFixtures      []string
		changeRateThreshold float64
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "fail on removed root",
			args: args{
				baselineFixtures:    []string{"testdata/fixtures/target-added"},
				targetFixtures:      []string{"testdata/fixtures/baseline"},
				changeRateThreshold: 10,
			},
			wantErr: true,
		},
		{
			name: "pass identical",
			args: args{
				baselineFixtures:    []string{"testdata/fixtures/baseline"},
				targetFixtures:      []string{"testdata/fixtures/target-same"},
				changeRateThreshold: 10,
			},
			wantErr: false,
		},
		{
			// Target-only ecosystems are excluded from change rate calculation (baseline-only policy).
			name: "pass target-only ecosystem ignored",
			args: args{
				baselineFixtures:    []string{"testdata/fixtures/baseline"},                                      // alma:8
				targetFixtures:      []string{"testdata/fixtures/baseline", "testdata/fixtures/change-baseline"}, // alma:8 + test:change
				changeRateThreshold: 0,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baselinePath := filepath.Join(t.TempDir(), "vuls.db")
			if err := populateDB(baselinePath, tt.args.baselineFixtures...); err != nil {
				t.Fatal(err)
			}
			targetPath := filepath.Join(t.TempDir(), "vuls.db")
			if err := populateDB(targetPath, tt.args.targetFixtures...); err != nil {
				t.Fatal(err)
			}

			gotErr := db.DiffBoltDB(
				baselinePath, targetPath,
				db.WithChangeRateThreshold(tt.args.changeRateThreshold),
				db.WithWriter(&bytes.Buffer{}),
			)

			if (gotErr != nil) != tt.wantErr {
				t.Fatalf("DiffBoltDB() error = %v, wantErr %v", gotErr, tt.wantErr)
			}
		})
	}
}

func TestCompareCriterions(t *testing.T) {
	type args struct {
		baseline string
		target   string
	}
	tests := []struct {
		name         string
		args         args
		wantBaseline int
		wantTarget   int
		wantMatched  int
		wantErr      bool
	}{
		{
			name: "identical",
			args: args{
				baseline: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					]
				}`,
				target: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					]
				}`,
			},
			wantBaseline: 1,
			wantTarget:   1,
			wantMatched:  1,
		},
		{
			name: "criteria removed",
			args: args{
				baseline: `{
					"src1": [
						{"criteria": {"operator": "AND", "criterions": [{"type": "version"}]}},
						{"criteria": {"operator": "OR",  "criterions": [{"type": "version"}]}}
					]
				}`,
				target: `{
					"src1": [
						{"criteria": {"operator": "AND", "criterions": [{"type": "version"}]}}
					]
				}`,
			},
			wantBaseline: 2,
			wantTarget:   1,
			wantMatched:  1,
		},
		{
			name: "criteria added in target",
			args: args{
				baseline: `{
					"src1": [
						{"criteria": {"operator": "AND", "criterions": [{"type": "version"}]}}
					]
				}`,
				target: `{
					"src1": [
						{"criteria": {"operator": "AND", "criterions": [{"type": "version"}]}},
						{"criteria": {"operator": "OR",  "criterions": [{"type": "version"}]}}
					]
				}`,
			},
			wantBaseline: 1,
			wantTarget:   2,
			wantMatched:  1,
		},
		{
			name: "operator changed only (criterions identical)",
			args: args{
				baseline: `{
					"src1": [
						{"criteria": {"operator": "AND", "criterions": [{"type": "version"}]}}
					]
				}`,
				target: `{
					"src1": [
						{"criteria": {"operator": "OR", "criterions": [{"type": "version"}]}}
					]
				}`,
			},
			wantBaseline: 1,
			wantTarget:   1,
			wantMatched:  0,
		},
		{
			name: "criterion type changed",
			args: args{
				baseline: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					]
				}`,
				target: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "none-exist"}]}}
					]
				}`,
			},
			wantBaseline: 1,
			wantTarget:   1,
			wantMatched:  0,
		},
		{
			name: "source removed",
			args: args{
				baseline: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					],
					"src2": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					]
				}`,
				target: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					]
				}`,
			},
			wantBaseline: 2,
			wantTarget:   1,
			wantMatched:  1,
		},
		{
			name: "target invalid data",
			args: args{
				baseline: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					]
				}`,
				target: `not json`,
			},
			wantBaseline: 0,
			wantTarget:   0,
			wantMatched:  0,
			wantErr:      true,
		},
		{
			name: "baseline invalid data",
			args: args{
				baseline: `not json`,
				target: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					]
				}`,
			},
			wantBaseline: 0,
			wantTarget:   0,
			wantMatched:  0,
			wantErr:      true,
		},
		{
			name: "empty baseline",
			args: args{
				baseline: `{}`,
				target: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					]
				}`,
			},
			wantBaseline: 0,
			wantTarget:   1,
			wantMatched:  0,
		},
		{
			name: "kb criterion identical",
			args: args{
				baseline: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "kb", "kb": {"product": "Windows 11", "kb_id": "KB5001234"}}]}}
					]
				}`,
				target: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "kb", "kb": {"product": "Windows 11", "kb_id": "KB5001234"}}]}}
					]
				}`,
			},
			wantBaseline: 1,
			wantTarget:   1,
			wantMatched:  1,
		},
		{
			name: "kb criterion changed",
			args: args{
				baseline: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "kb", "kb": {"product": "Windows 11", "kb_id": "KB5001234"}}]}}
					]
				}`,
				target: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "kb", "kb": {"product": "Windows 11", "kb_id": "KB5005678"}}]}}
					]
				}`,
			},
			wantBaseline: 1,
			wantTarget:   1,
			wantMatched:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseline, target, matched, err := db.CompareCriterions([]byte(tt.args.baseline), []byte(tt.args.target))
			if (err != nil) != tt.wantErr {
				t.Fatalf("CompareCriterions() error = %v, wantErr %v", err, tt.wantErr)
			}
			if baseline != tt.wantBaseline {
				t.Errorf("baseline = %d, want %d", baseline, tt.wantBaseline)
			}
			if target != tt.wantTarget {
				t.Errorf("target = %d, want %d", target, tt.wantTarget)
			}
			if matched != tt.wantMatched {
				t.Errorf("matched = %d, want %d", matched, tt.wantMatched)
			}
		})
	}
}

func TestCountCriterions(t *testing.T) {
	type args struct {
		data string
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			name: "empty",
			args: args{data: `{}`},
			want: 0,
		},
		{
			name: "no conditions",
			args: args{data: `{"src1":[]}`},
			want: 0,
		},
		{
			name: "one criterion",
			args: args{data: `{
				"src1": [
					{"criteria": {"criterions": [{"type": "version"}]}}
				]
			}`},
			want: 1,
		},
		{
			name: "nested criteria counts all leaf criterions",
			args: args{data: `{
				"src1": [
					{"criteria": {"operator": "OR", "criterias": [
						{"criterions": [{"type": "version"}, {"type": "version"}]},
						{"criterions": [{"type": "version"}]}
					]}}
				]
			}`},
			want: 3,
		},
		{
			name: "multiple sources",
			args: args{data: `{
				"src1": [
					{"criteria": {"criterions": [{"type": "version"}]}}
				],
				"src2": [
					{"criteria": {"criterions": [{"type": "version"}, {"type": "version"}]}}
				]
			}`},
			want: 3,
		},
		{
			name: "multiple conditions per source",
			args: args{data: `{
				"src1": [
					{"criteria": {"criterions": [{"type": "version"}]}},
					{"criteria": {"criterions": [{"type": "version"}]}}
				]
			}`},
			want: 2,
		},
		{
			name: "kb criterion",
			args: args{data: `{
				"src1": [
					{"criteria": {"criterions": [{"type": "kb", "kb": {"product": "Windows 11", "kb_id": "KB5001234"}}]}}
				]
			}`},
			want: 1,
		},
		{
			name:    "invalid json",
			args:    args{data: `not json`},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.CountCriterions([]byte(tt.args.data))
			if (err != nil) != tt.wantErr {
				t.Fatalf("CountCriterions() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("CountCriterions() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCompareKBs(t *testing.T) {
	type args struct {
		baseline string
		target   string
	}
	tests := []struct {
		name         string
		args         args
		wantBaseline int
		wantTarget   int
		wantMatched  int
		wantErr      bool
	}{
		{
			name: "identical single source",
			args: args{
				baseline: `{
					"src1": {
						"kb_id": "KB5001234",
						"url": "https://example.com",
						"products": ["Windows 11"]
					}
				}`,
				target: `{
					"src1": {
						"kb_id": "KB5001234",
						"url": "https://example.com",
						"products": ["Windows 11"]
					}
				}`,
			},
			wantBaseline: 1,
			wantTarget:   1,
			wantMatched:  1,
		},
		{
			name: "products differ",
			args: args{
				baseline: `{
					"src1": {
						"kb_id": "KB5001234",
						"products": ["Windows 11"]
					}
				}`,
				target: `{
					"src1": {
						"kb_id": "KB5001234",
						"products": ["Windows 11", "Windows Server"]
					}
				}`,
			},
			wantBaseline: 1,
			wantTarget:   1,
			wantMatched:  0,
		},
		{
			name: "products reordered still match after Sort",
			args: args{
				baseline: `{
					"src1": {
						"kb_id": "KB5001234",
						"products": ["Windows Server", "Windows 11"]
					}
				}`,
				target: `{
					"src1": {
						"kb_id": "KB5001234",
						"products": ["Windows 11", "Windows Server"]
					}
				}`,
			},
			wantBaseline: 1,
			wantTarget:   1,
			wantMatched:  1,
		},
		{
			name: "superseded_by differs only",
			args: args{
				baseline: `{
					"src1": {
						"kb_id": "KB5001234",
						"superseded_by": [
							{"kb_id": "KB5002000"}
						]
					}
				}`,
				target: `{
					"src1": {
						"kb_id": "KB5001234",
						"superseded_by": [
							{"kb_id": "KB5002000"},
							{"kb_id": "KB5003000"}
						]
					}
				}`,
			},
			wantBaseline: 1,
			wantTarget:   1,
			wantMatched:  0,
		},
		{
			name: "source added in target",
			args: args{
				baseline: `{
					"src1": {"kb_id": "KB5001234"}
				}`,
				target: `{
					"src1": {"kb_id": "KB5001234"},
					"src2": {"kb_id": "KB5001234"}
				}`,
			},
			wantBaseline: 1,
			wantTarget:   2,
			wantMatched:  1,
		},
		{
			name: "source removed in target",
			args: args{
				baseline: `{
					"src1": {"kb_id": "KB5001234"},
					"src2": {"kb_id": "KB5001234"}
				}`,
				target: `{
					"src1": {"kb_id": "KB5001234"}
				}`,
			},
			wantBaseline: 2,
			wantTarget:   1,
			wantMatched:  1,
		},
		{
			name: "baseline invalid data",
			args: args{
				baseline: `not json`,
				target: `{
					"src1": {"kb_id": "KB5001234"}
				}`,
			},
			wantErr: true,
		},
		{
			name: "target invalid data",
			args: args{
				baseline: `{
					"src1": {"kb_id": "KB5001234"}
				}`,
				target: `not json`,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseline, target, matched, err := db.CompareKBs([]byte(tt.args.baseline), []byte(tt.args.target))
			if (err != nil) != tt.wantErr {
				t.Fatalf("CompareKBs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if baseline != tt.wantBaseline {
				t.Errorf("baseline = %d, want %d", baseline, tt.wantBaseline)
			}
			if target != tt.wantTarget {
				t.Errorf("target = %d, want %d", target, tt.wantTarget)
			}
			if matched != tt.wantMatched {
				t.Errorf("matched = %d, want %d", matched, tt.wantMatched)
			}
		})
	}
}

func TestCountKBs(t *testing.T) {
	type args struct {
		data string
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			name: "empty",
			args: args{data: `{}`},
			want: 0,
		},
		{
			name: "one source",
			args: args{data: `{
				"src1": {"kb_id": "KB5001234"}
			}`},
			want: 1,
		},
		{
			name: "multiple sources",
			args: args{data: `{
				"src1": {"kb_id": "KB5001234"},
				"src2": {"kb_id": "KB5001234"}
			}`},
			want: 2,
		},
		{
			name:    "invalid json",
			args:    args{data: `not json`},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.CountKBs([]byte(tt.args.data))
			if (err != nil) != tt.wantErr {
				t.Fatalf("CountKBs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("CountKBs() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestGenerateReport(t *testing.T) {
	type args struct {
		diffs               []db.EcosystemDiff
		changeRateThreshold float64
	}
	tests := []struct {
		name       string
		args       args
		wantPass   bool
		wantReport string
	}{
		{
			name: "fail with details",
			args: args{
				diffs: []db.EcosystemDiff{
					{
						Ecosystem:           "redhat:9",
						BaselineKeys:        100,
						TargetKeys:          100,
						BaselineCriterions:  500,
						TargetCriterions:    500,
						MatchedCriterions:   500,
						DetectionChangeRate: 0,
						Pass:                true,
					},
					{
						Ecosystem:           "ubuntu:22.04",
						BaselineKeys:        800,
						TargetKeys:          200,
						BaselineCriterions:  4000,
						TargetCriterions:    2000,
						MatchedCriterions:   1000,
						Removed:             []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"},
						Changed:             []string{"CVE-2024-0004"},
						DetectionChangeRate: 75.0,
						Pass:                false,
					},
				},
				changeRateThreshold: 10,
			},
			wantPass: false,
			wantReport: `# Diff Report: DB

**Result**: **FAIL**
**Change Rate Threshold**:     10.0%
**Detection Change Rate Max**: 75.0% (ubuntu:22.04)
**KB Change Rate Max**:        0.0%

## Summary

| Ecosystem | Detection Change Rate | KB Change Rate | Result |
|-----------|-----------------------|----------------|--------|
| ubuntu:22.04 | 75.0% | 0.0% | **FAIL** |
| redhat:9 | 0.0% | 0.0% | PASS |

## Detection

| Ecosystem | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
| ubuntu:22.04 | 800 | 200 | 0 | 3 | 1 | 4000 | 2000 | 1000 |
| redhat:9 | 100 | 100 | 0 | 0 | 0 | 500 | 500 | 500 |

## Details (FAIL ecosystems)

### ubuntu:22.04

#### Removed Root IDs (3)

- CVE-2024-0001
- CVE-2024-0002
- CVE-2024-0003

#### Changed Root IDs (1)

- CVE-2024-0004

`,
		},
		{
			name: "pass all ecosystems",
			args: args{
				diffs: []db.EcosystemDiff{
					{
						Ecosystem:           "alma:8",
						BaselineKeys:        50,
						TargetKeys:          52,
						Added:               []string{"ALSA-2025-0001", "ALSA-2025-0002"},
						BaselineCriterions:  200,
						TargetCriterions:    210,
						MatchedCriterions:   200,
						DetectionChangeRate: 4.8,
						Pass:                true,
					},
				},
				changeRateThreshold: 10,
			},
			wantPass: true,
			wantReport: `# Diff Report: DB

**Result**: PASS
**Change Rate Threshold**:     10.0%
**Detection Change Rate Max**: 4.8% (alma:8)
**KB Change Rate Max**:        0.0%

## Summary

| Ecosystem | Detection Change Rate | KB Change Rate | Result |
|-----------|-----------------------|----------------|--------|
| alma:8 | 4.8% | 0.0% | PASS |

## Detection

| Ecosystem | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
| alma:8 | 50 | 52 | 2 | 0 | 0 | 200 | 210 | 200 |

`,
		},
		{
			name: "fail with kb changes",
			args: args{
				diffs: []db.EcosystemDiff{
					{
						Ecosystem:      "microsoft",
						BaselineKBKeys: 10,
						TargetKBKeys:   10,
						BaselineKBs:    10,
						TargetKBs:      10,
						MatchedKBs:     3,
						ChangedKBs:     []string{"KB5001", "KB5002"},
						AddedKBs:       []string{"KB5003"},
						RemovedKBs:     []string{"KB4000"},
						KBChangeRate:   140.0,
						Pass:           false,
					},
				},
				changeRateThreshold: 10,
			},
			wantPass: false,
			wantReport: `# Diff Report: DB

**Result**: **FAIL**
**Change Rate Threshold**:     10.0%
**Detection Change Rate Max**: 0.0%
**KB Change Rate Max**:        140.0% (microsoft)

## Summary

| Ecosystem | Detection Change Rate | KB Change Rate | Result |
|-----------|-----------------------|----------------|--------|
| microsoft | 0.0% | 140.0% | **FAIL** |

## KB

| Ecosystem | Baseline KB Keys | Target KB Keys | Added | Removed | Changed | Baseline KBs | Target KBs | Matched KBs |
|-----------|------------------|----------------|-------|---------|---------|--------------|------------|-------------|
| microsoft | 10 | 10 | 1 | 1 | 2 | 10 | 10 | 3 |

## Details (FAIL ecosystems)

### microsoft

#### Added KB IDs (1)

- KB5003

#### Removed KB IDs (1)

- KB4000

#### Changed KB IDs (2)

- KB5001
- KB5002

`,
		},
		{
			name: "pass with detection and kb",
			args: args{
				diffs: []db.EcosystemDiff{
					{
						Ecosystem:          "alma:8",
						BaselineKeys:       10,
						TargetKeys:         10,
						BaselineCriterions: 50,
						TargetCriterions:   50,
						MatchedCriterions:  50,
						Pass:               true,
					},
					{
						Ecosystem:      "microsoft",
						BaselineKBKeys: 5,
						TargetKBKeys:   5,
						BaselineKBs:    5,
						TargetKBs:      5,
						MatchedKBs:     5,
						Pass:           true,
					},
				},
				changeRateThreshold: 10,
			},
			wantPass: true,
			wantReport: `# Diff Report: DB

**Result**: PASS
**Change Rate Threshold**:     10.0%
**Detection Change Rate Max**: 0.0%
**KB Change Rate Max**:        0.0%

## Summary

| Ecosystem | Detection Change Rate | KB Change Rate | Result |
|-----------|-----------------------|----------------|--------|
| alma:8 | 0.0% | 0.0% | PASS |
| microsoft | 0.0% | 0.0% | PASS |

## Detection

| Ecosystem | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
| alma:8 | 10 | 10 | 0 | 0 | 0 | 50 | 50 | 50 |

## KB

| Ecosystem | Baseline KB Keys | Target KB Keys | Added | Removed | Changed | Baseline KBs | Target KBs | Matched KBs |
|-----------|------------------|----------------|-------|---------|---------|--------------|------------|-------------|
| microsoft | 5 | 5 | 0 | 0 | 0 | 5 | 5 | 5 |

`,
		},
		{
			// Demonstrates why detection and KB rates must be reported
			// separately: detection change (1.5%) is well within threshold,
			// but KB change (80%) in a much smaller bucket indicates a real
			// regression that a combined rate would dilute.
			name: "fail only on kb despite passing detection",
			args: args{
				diffs: []db.EcosystemDiff{
					{
						Ecosystem:           "mixed:1",
						BaselineKeys:        100,
						TargetKeys:          100,
						BaselineCriterions:  10000,
						TargetCriterions:    10050,
						MatchedCriterions:   9950,
						BaselineKBKeys:      5,
						TargetKBKeys:        5,
						BaselineKBs:         5,
						TargetKBs:           5,
						MatchedKBs:          3,
						ChangedKBs:          []string{"KB1", "KB2"},
						DetectionChangeRate: 1.5,
						KBChangeRate:        80.0,
						Pass:                false,
					},
				},
				changeRateThreshold: 10,
			},
			wantPass: false,
			wantReport: `# Diff Report: DB

**Result**: **FAIL**
**Change Rate Threshold**:     10.0%
**Detection Change Rate Max**: 1.5% (mixed:1)
**KB Change Rate Max**:        80.0% (mixed:1)

## Summary

| Ecosystem | Detection Change Rate | KB Change Rate | Result |
|-----------|-----------------------|----------------|--------|
| mixed:1 | 1.5% | 80.0% | **FAIL** |

## Detection

| Ecosystem | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
| mixed:1 | 100 | 100 | 0 | 0 | 0 | 10000 | 10050 | 9950 |

## KB

| Ecosystem | Baseline KB Keys | Target KB Keys | Added | Removed | Changed | Baseline KBs | Target KBs | Matched KBs |
|-----------|------------------|----------------|-------|---------|---------|--------------|------------|-------------|
| mixed:1 | 5 | 5 | 0 | 0 | 2 | 5 | 5 | 3 |

## Details (FAIL ecosystems)

### mixed:1

#### Changed KB IDs (2)

- KB1
- KB2

`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			gotPass, err := db.GenerateReport(&buf, tt.args.diffs, tt.args.changeRateThreshold)
			if err != nil {
				t.Fatalf("GenerateReport() error = %v", err)
			}
			if gotPass != tt.wantPass {
				t.Errorf("GenerateReport() pass = %v, want %v", gotPass, tt.wantPass)
			}
			got := buf.String()
			if diff := cmp.Diff(tt.wantReport, got); diff != "" {
				t.Errorf("GenerateReport() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
