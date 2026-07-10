package db_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

	"github.com/MaineK00n/vuls2/pkg/db/session"
	db "github.com/MaineK00n/vuls2/pkg/diff/db"
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
		overrides       map[string]float64 // resolved against a default threshold of 0
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
				Ecosystem: "alma:8",
				Sources: []db.SourceDiff{
					{
						SourceID:           "alma-errata",
						BaselineKeys:       1,
						TargetKeys:         1,
						BaselineCriterions: 6,
						TargetCriterions:   6,
						MatchedCriterions:  6,
						Pass:               true,
					},
				},
				Pass: true,
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
				Ecosystem: "alma:8",
				Sources: []db.SourceDiff{
					{
						SourceID:            "alma-errata",
						BaselineKeys:        1,
						TargetKeys:          1,
						Added:               []string{"ALSA-2019:3708"},
						Removed:             []string{"ALSA-2024:0113"},
						BaselineCriterions:  6,
						TargetCriterions:    6,
						DetectionChangeRate: 200,
					},
				},
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
				Ecosystem: "alma:8",
				Sources: []db.SourceDiff{
					{
						SourceID:            "alma-errata",
						BaselineKeys:        1,
						TargetKeys:          1,
						Changed:             []string{"ALSA-2024:0113"},
						BaselineCriterions:  6,
						TargetCriterions:    6,
						MatchedCriterions:   5,
						DetectionChangeRate: float64(6-5+6-5) / float64(6) * 100,
					},
				},
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
				Ecosystem: "alma:8",
				Sources: []db.SourceDiff{
					{
						SourceID:            "alma-errata",
						BaselineKeys:        1,
						Removed:             []string{"ALSA-2024:0113"},
						BaselineCriterions:  6,
						DetectionChangeRate: 100,
					},
				},
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
				Ecosystem: "alma:8",
				Sources: []db.SourceDiff{
					{
						SourceID:            "alma-errata",
						BaselineKeys:        1,
						TargetKeys:          2,
						Added:               []string{"ALSA-2019:3708"},
						BaselineCriterions:  6,
						TargetCriterions:    12,
						MatchedCriterions:   6,
						DetectionChangeRate: 100,
					},
				},
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
				Ecosystem: "test:change",
				Sources: []db.SourceDiff{
					{
						SourceID:            "test-source",
						BaselineKeys:        2,
						TargetKeys:          2,
						Changed:             []string{"ROOT-0001", "ROOT-0002"},
						BaselineCriterions:  6,
						TargetCriterions:    2,
						MatchedCriterions:   0,
						DetectionChangeRate: float64(6-0+2-0) / float64(6) * 100,
					},
				},
			},
		},
		{
			// Two sources share one root ID; only the changed one may fail,
			// the unchanged one must pass, and a source newly appearing in
			// target is strict-failed.
			name: "multi-source: only changed source fails",
			args: args{
				baselineFixture: "testdata/fixtures/multi-source-baseline",
				targetFixture:   "testdata/fixtures/multi-source-target",
				ecosystem:       "test:multi",
			},
			want: db.EcosystemDiff{
				Ecosystem: "test:multi",
				Sources: []db.SourceDiff{
					{
						SourceID:           "test-source-1",
						BaselineKeys:       1,
						TargetKeys:         1,
						BaselineCriterions: 1,
						TargetCriterions:   1,
						MatchedCriterions:  1,
						Pass:               true,
					},
					{
						SourceID:            "test-source-2",
						BaselineKeys:        1,
						TargetKeys:          1,
						Changed:             []string{"ROOT-0001"},
						BaselineCriterions:  1,
						TargetCriterions:    1,
						DetectionChangeRate: 200,
					},
					{
						SourceID:            "test-source-3",
						TargetKeys:          1,
						Added:               []string{"ROOT-0001"},
						TargetCriterions:    1,
						DetectionChangeRate: 100,
					},
				},
			},
		},
		{
			name: "multi-source: per-source thresholds lift failing sources",
			args: args{
				baselineFixture: "testdata/fixtures/multi-source-baseline",
				targetFixture:   "testdata/fixtures/multi-source-target",
				ecosystem:       "test:multi",
				overrides: map[string]float64{
					"test:multi/test-source-2": 250,
					"test:multi/test-source-3": 150,
				},
			},
			want: db.EcosystemDiff{
				Ecosystem: "test:multi",
				Sources: []db.SourceDiff{
					{
						SourceID:           "test-source-1",
						BaselineKeys:       1,
						TargetKeys:         1,
						BaselineCriterions: 1,
						TargetCriterions:   1,
						MatchedCriterions:  1,
						Pass:               true,
					},
					{
						SourceID:            "test-source-2",
						BaselineKeys:        1,
						TargetKeys:          1,
						Changed:             []string{"ROOT-0001"},
						BaselineCriterions:  1,
						TargetCriterions:    1,
						DetectionChangeRate: 200,
						Threshold:           250,
						Pass:                true,
					},
					{
						SourceID:            "test-source-3",
						TargetKeys:          1,
						Added:               []string{"ROOT-0001"},
						TargetCriterions:    1,
						DetectionChangeRate: 100,
						Threshold:           150,
						Pass:                true,
					},
				},
				Pass: true,
			},
		},
		{
			// A source present with zero criterions (extraction bug shipped
			// in real data, e.g. fedora-api advisories without packages) is
			// skipped with a warning: it must appear neither as a SourceDiff
			// nor fail the diff.
			name: "zero-criterion source skipped",
			args: args{
				baselineFixture: "testdata/fixtures/zero-unit-baseline",
				targetFixture:   "testdata/fixtures/zero-unit-target",
				ecosystem:       "test:zero",
			},
			want: db.EcosystemDiff{
				Ecosystem: "test:zero",
				Sources: []db.SourceDiff{
					{
						SourceID:           "test-source-1",
						BaselineKeys:       1,
						TargetKeys:         1,
						BaselineCriterions: 1,
						TargetCriterions:   1,
						MatchedCriterions:  1,
						Pass:               true,
					},
				},
				Pass: true,
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
				Ecosystem: "microsoft",
				Sources: []db.SourceDiff{
					{
						SourceID:       "microsoft-cvrf",
						BaselineKBKeys: 2,
						TargetKBKeys:   2,
						MatchedKBs:     2,
						Pass:           true,
					},
				},
				Pass: true,
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
				Ecosystem: "microsoft",
				Sources: []db.SourceDiff{
					{
						SourceID:       "microsoft-cvrf",
						BaselineKBKeys: 2,
						TargetKBKeys:   3,
						AddedKBs:       []string{"KB5001222"},
						MatchedKBs:     2,
						KBChangeRate:   50,
					},
				},
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
				Ecosystem: "microsoft",
				Sources: []db.SourceDiff{
					{
						SourceID:       "microsoft-cvrf",
						BaselineKBKeys: 2,
						TargetKBKeys:   2,
						ChangedKBs:     []string{"KB5001111"},
						MatchedKBs:     1,
						KBChangeRate:   100,
					},
				},
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
				Ecosystem: "microsoft",
				Sources: []db.SourceDiff{
					{
						SourceID:       "microsoft-cvrf",
						BaselineKBKeys: 2,
						RemovedKBs:     []string{"KB5001000", "KB5001111"},
						KBChangeRate:   100,
					},
				},
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

			got, err := db.DiffEcosystem(bdb, tdb, tt.args.ecosystem, tt.args.overrides, 0)
			if err != nil {
				t.Fatal(err)
			}

			// Sources carries no order guarantee (the report sorts for
			// presentation), so compare it order-insensitively.
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(a, b db.SourceDiff) bool { return a.SourceID < b.SourceID })); diff != "" {
				t.Errorf("DiffEcosystem() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDiffBoltDB(t *testing.T) {
	type args struct {
		baselineFixtures             []string
		targetFixtures               []string
		changeRateThreshold          float64
		changeRateThresholdOverrides map[string]float64
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
		{
			// target-replaced gives alma:8/alma-errata a 200% detection change
			// rate; with the default threshold 10% this normally fails.
			name: "ecosystem override lifts its sources above threshold",
			args: args{
				baselineFixtures:             []string{"testdata/fixtures/baseline"},
				targetFixtures:               []string{"testdata/fixtures/target-replaced"},
				changeRateThreshold:          10,
				changeRateThresholdOverrides: map[string]float64{"alma:8": 250},
			},
			wantErr: false,
		},
		{
			// Override below the actual rate must still fail.
			name: "override below rate still fails",
			args: args{
				baselineFixtures:             []string{"testdata/fixtures/baseline"},
				targetFixtures:               []string{"testdata/fixtures/target-replaced"},
				changeRateThreshold:          10,
				changeRateThresholdOverrides: map[string]float64{"alma:8": 100},
			},
			wantErr: true,
		},
		{
			// An override targeting an ecosystem not present in baseline must
			// not change pass/fail of other ecosystems.
			name: "unmatched override key does not affect outcome",
			args: args{
				baselineFixtures:             []string{"testdata/fixtures/baseline"},
				targetFixtures:               []string{"testdata/fixtures/target-same"},
				changeRateThreshold:          10,
				changeRateThresholdOverrides: map[string]float64{"unknown:99": 50},
			},
			wantErr: false,
		},
		{
			// multi-source rates: test-source-1 0%, test-source-2 200%
			// (changed), test-source-3 100% (new source in target). An
			// ecosystem-wide override is the default for all its sources.
			name: "ecosystem override covers all sources",
			args: args{
				baselineFixtures:             []string{"testdata/fixtures/multi-source-baseline"},
				targetFixtures:               []string{"testdata/fixtures/multi-source-target"},
				changeRateThreshold:          10,
				changeRateThresholdOverrides: map[string]float64{"test:multi": 250},
			},
			wantErr: false,
		},
		{
			// Per-source overrides lift exactly the failing sources while the
			// unchanged source stays on the default threshold.
			name: "per-source overrides lift failing sources",
			args: args{
				baselineFixtures:    []string{"testdata/fixtures/multi-source-baseline"},
				targetFixtures:      []string{"testdata/fixtures/multi-source-target"},
				changeRateThreshold: 10,
				changeRateThresholdOverrides: map[string]float64{
					"test:multi/test-source-2": 250,
					"test:multi/test-source-3": 150,
				},
			},
			wantErr: false,
		},
		{
			// The lenient direction of the same precedence: the ecosystem-wide
			// override alone (50) would fail test-source-2 (200%) and
			// test-source-3 (100%), but their source-specific overrides win
			// and lift both above their rates.
			name: "source override rescues from strict ecosystem override",
			args: args{
				baselineFixtures:    []string{"testdata/fixtures/multi-source-baseline"},
				targetFixtures:      []string{"testdata/fixtures/multi-source-target"},
				changeRateThreshold: 10,
				changeRateThresholdOverrides: map[string]float64{
					"test:multi":               50,
					"test:multi/test-source-2": 250,
					"test:multi/test-source-3": 150,
				},
			},
			wantErr: false,
		},
		{
			// A source-specific override takes precedence over a generous
			// ecosystem-wide override: test-source-2 (200%) fails at 100 even
			// though the ecosystem override of 300 would pass it.
			name: "source override beats ecosystem override",
			args: args{
				baselineFixtures:    []string{"testdata/fixtures/multi-source-baseline"},
				targetFixtures:      []string{"testdata/fixtures/multi-source-target"},
				changeRateThreshold: 10,
				changeRateThresholdOverrides: map[string]float64{
					"test:multi":               300,
					"test:multi/test-source-2": 100,
				},
			},
			wantErr: true,
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
				db.WithChangeRateThresholdOverrides(tt.args.changeRateThresholdOverrides),
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
		name    string
		args    args
		want    map[sourceTypes.SourceID]db.Tally
		wantErr bool
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 1},
			},
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 2, Target: 1, Matched: 1},
			},
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 2, Matched: 1},
			},
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 0},
			},
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 0},
			},
		},
		{
			// A removed source surfaces as its own entry with a
			// baseline-only tally.
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 1},
				"src2": {Baseline: 1},
			},
		},
		{
			name: "source added",
			args: args{
				baseline: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					]
				}`,
				target: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					],
					"src2": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					]
				}`,
			},
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 1},
				"src2": {Target: 1},
			},
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
			wantErr: true,
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
			wantErr: true,
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Target: 1},
			},
		},
		{
			// A present source with zero criterions yields a zero tally on
			// that side; the accumulation sites treat it as absent.
			name: "present source without criterions yields zero tally",
			args: args{
				baseline: `{
					"src1": []
				}`,
				target: `{
					"src1": [
						{"criteria": {"criterions": [{"type": "version"}]}}
					]
				}`,
			},
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 0, Target: 1, Matched: 0},
			},
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 1},
			},
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 0},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.CompareCriterions([]byte(tt.args.baseline), []byte(tt.args.target))
			if (err != nil) != tt.wantErr {
				t.Fatalf("CompareCriterions() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("CompareCriterions() mismatch (-want +got):\n%s", diff)
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
		want    map[sourceTypes.SourceID]int
		wantErr bool
	}{
		{
			name: "empty",
			args: args{data: `{}`},
			want: map[sourceTypes.SourceID]int{},
		},
		{
			// A present source with zero criterions is kept as an explicit
			// zero — the accumulation sites skip it with a warning.
			name: "no conditions",
			args: args{data: `{"src1":[]}`},
			want: map[sourceTypes.SourceID]int{"src1": 0},
		},
		{
			name: "one criterion",
			args: args{data: `{
				"src1": [
					{"criteria": {"criterions": [{"type": "version"}]}}
				]
			}`},
			want: map[sourceTypes.SourceID]int{"src1": 1},
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
			want: map[sourceTypes.SourceID]int{"src1": 3},
		},
		{
			name: "multiple sources counted separately",
			args: args{data: `{
				"src1": [
					{"criteria": {"criterions": [{"type": "version"}]}}
				],
				"src2": [
					{"criteria": {"criterions": [{"type": "version"}, {"type": "version"}]}}
				]
			}`},
			want: map[sourceTypes.SourceID]int{"src1": 1, "src2": 2},
		},
		{
			name: "multiple conditions per source",
			args: args{data: `{
				"src1": [
					{"criteria": {"criterions": [{"type": "version"}]}},
					{"criteria": {"criterions": [{"type": "version"}]}}
				]
			}`},
			want: map[sourceTypes.SourceID]int{"src1": 2},
		},
		{
			name: "kb criterion",
			args: args{data: `{
				"src1": [
					{"criteria": {"criterions": [{"type": "kb", "kb": {"product": "Windows 11", "kb_id": "KB5001234"}}]}}
				]
			}`},
			want: map[sourceTypes.SourceID]int{"src1": 1},
		},
		{
			name:    "invalid json",
			args:    args{data: `not json`},
			wantErr: true,
		},
		{
			// The writer always stores marshaled JSON; a zero-length value is
			// corrupt and must not be silently skipped by the guard.
			name:    "zero-length value",
			args:    args{data: ``},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.CountCriterions([]byte(tt.args.data))
			if (err != nil) != tt.wantErr {
				t.Fatalf("CountCriterions() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("CountCriterions() mismatch (-want +got):\n%s", diff)
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
		name    string
		args    args
		want    map[sourceTypes.SourceID]db.Tally
		wantErr bool
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 1},
			},
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 0},
			},
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 1},
			},
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 0},
			},
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 1},
				"src2": {Target: 1},
			},
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
			want: map[sourceTypes.SourceID]db.Tally{
				"src1": {Baseline: 1, Target: 1, Matched: 1},
				"src2": {Baseline: 1},
			},
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
			got, err := db.CompareKBs([]byte(tt.args.baseline), []byte(tt.args.target))
			if (err != nil) != tt.wantErr {
				t.Fatalf("CompareKBs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("CompareKBs() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestKBSources(t *testing.T) {
	type args struct {
		data string
	}
	tests := []struct {
		name    string
		args    args
		want    []sourceTypes.SourceID
		wantErr bool
	}{
		{
			name: "empty",
			args: args{data: `{}`},
			want: nil,
		},
		{
			name: "one source",
			args: args{data: `{
				"src1": {"kb_id": "KB5001234"}
			}`},
			want: []sourceTypes.SourceID{"src1"},
		},
		{
			name: "multiple sources",
			args: args{data: `{
				"src1": {"kb_id": "KB5001234"},
				"src2": {"kb_id": "KB5001234"}
			}`},
			want: []sourceTypes.SourceID{"src1", "src2"},
		},
		{
			name:    "invalid json",
			args:    args{data: `not json`},
			wantErr: true,
		},
		{
			// Same policy as countCriterions: empty means corrupt, not "skip".
			name:    "zero-length value",
			args:    args{data: ``},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.KBSources([]byte(tt.args.data))
			if (err != nil) != tt.wantErr {
				t.Fatalf("KBSources() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			// Map key order is random; compare order-insensitively.
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(a, b sourceTypes.SourceID) bool { return a < b })); diff != "" {
				t.Errorf("KBSources() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGenerateReport(t *testing.T) {
	type args struct {
		diffs []db.EcosystemDiff
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
						Ecosystem: "redhat:9",
						Sources: []db.SourceDiff{
							{
								SourceID:            "redhat-ovalv2",
								BaselineKeys:        100,
								TargetKeys:          100,
								BaselineCriterions:  500,
								TargetCriterions:    500,
								MatchedCriterions:   500,
								DetectionChangeRate: 0,
								Threshold:           10,
								Pass:                true,
							},
						},
						Pass: true,
					},
					{
						Ecosystem: "ubuntu:22.04",
						Sources: []db.SourceDiff{
							{
								SourceID:            "ubuntu-oval",
								BaselineKeys:        800,
								TargetKeys:          200,
								BaselineCriterions:  4000,
								TargetCriterions:    2000,
								MatchedCriterions:   1000,
								Removed:             []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"},
								Changed:             []string{"CVE-2024-0004"},
								DetectionChangeRate: 75.0,
								Threshold:           10,
								Pass:                false,
							},
						},
						Pass: false,
					},
				},
			},
			wantPass: false,
			wantReport: `# Diff Report: DB

## Summary

**Result**: **FAIL**

| Ecosystem | Source | Detection Change Rate | KB Change Rate | Threshold | Result |
|-----------|--------|-----------------------|----------------|-----------|--------|
| ubuntu:22.04 | ubuntu-oval | 75.0% | 0.0% | 10.0% | **FAIL** |
| redhat:9 | redhat-ovalv2 | 0.0% | 0.0% | 10.0% | PASS |

## Detection

| Ecosystem | Source | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|--------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
| ubuntu:22.04 | ubuntu-oval | 800 | 200 | 0 | 3 | 1 | 4000 | 2000 | 1000 |
| redhat:9 | redhat-ovalv2 | 100 | 100 | 0 | 0 | 0 | 500 | 500 | 500 |

## Details (FAIL sources)

### ubuntu:22.04 / ubuntu-oval (75.0%)

#### Removed Root IDs (3)

- CVE-2024-0001
- CVE-2024-0002
- CVE-2024-0003

#### Changed Root IDs (1)

- CVE-2024-0004

`,
		},
		{
			// Within a single ecosystem, a huge passing source must not mask
			// a small failing one — the failing small source sorts first.
			name: "small source failure not masked by large source",
			args: args{
				diffs: []db.EcosystemDiff{
					{
						Ecosystem: "cpe",
						Sources: []db.SourceDiff{
							{
								SourceID:            "cisco-json",
								BaselineKeys:        50,
								TargetKeys:          50,
								BaselineCriterions:  100,
								TargetCriterions:    100,
								MatchedCriterions:   70,
								Changed:             []string{"CVE-2024-1000"},
								DetectionChangeRate: 60.0,
								Threshold:           10,
								Pass:                false,
							},
							{
								SourceID:            "nvd-feed-cve-v2",
								BaselineKeys:        300000,
								TargetKeys:          300000,
								BaselineCriterions:  300000,
								TargetCriterions:    300000,
								MatchedCriterions:   299700,
								DetectionChangeRate: 0.2,
								Threshold:           10,
								Pass:                true,
							},
						},
						Pass: false,
					},
				},
			},
			wantPass: false,
			wantReport: `# Diff Report: DB

## Summary

**Result**: **FAIL**

| Ecosystem | Source | Detection Change Rate | KB Change Rate | Threshold | Result |
|-----------|--------|-----------------------|----------------|-----------|--------|
| cpe | cisco-json | 60.0% | 0.0% | 10.0% | **FAIL** |
| cpe | nvd-feed-cve-v2 | 0.2% | 0.0% | 10.0% | PASS |

## Detection

| Ecosystem | Source | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|--------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
| cpe | cisco-json | 50 | 50 | 0 | 0 | 1 | 100 | 100 | 70 |
| cpe | nvd-feed-cve-v2 | 300000 | 300000 | 0 | 0 | 0 | 300000 | 300000 | 299700 |

## Details (FAIL sources)

### cpe / cisco-json (60.0%)

#### Changed Root IDs (1)

- CVE-2024-1000

`,
		},
		{
			name: "pass all ecosystems",
			args: args{
				diffs: []db.EcosystemDiff{
					{
						Ecosystem: "alma:8",
						Sources: []db.SourceDiff{
							{
								SourceID:            "alma-errata",
								BaselineKeys:        50,
								TargetKeys:          52,
								Added:               []string{"ALSA-2025-0001", "ALSA-2025-0002"},
								BaselineCriterions:  200,
								TargetCriterions:    210,
								MatchedCriterions:   200,
								DetectionChangeRate: 4.8,
								Threshold:           10,
								Pass:                true,
							},
						},
						Pass: true,
					},
				},
			},
			wantPass: true,
			wantReport: `# Diff Report: DB

## Summary

**Result**: PASS

| Ecosystem | Source | Detection Change Rate | KB Change Rate | Threshold | Result |
|-----------|--------|-----------------------|----------------|-----------|--------|
| alma:8 | alma-errata | 4.8% | 0.0% | 10.0% | PASS |

## Detection

| Ecosystem | Source | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|--------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
| alma:8 | alma-errata | 50 | 52 | 2 | 0 | 0 | 200 | 210 | 200 |

`,
		},
		{
			name: "fail with kb changes",
			args: args{
				diffs: []db.EcosystemDiff{
					{
						Ecosystem: "microsoft",
						Sources: []db.SourceDiff{
							{
								SourceID:       "microsoft-cvrf",
								BaselineKBKeys: 10,
								TargetKBKeys:   10,
								MatchedKBs:     3,
								ChangedKBs:     []string{"KB5001", "KB5002"},
								AddedKBs:       []string{"KB5003"},
								RemovedKBs:     []string{"KB4000"},
								KBChangeRate:   140.0,
								Threshold:      10,
								Pass:           false,
							},
						},
						Pass: false,
					},
				},
			},
			wantPass: false,
			wantReport: `# Diff Report: DB

## Summary

**Result**: **FAIL**

| Ecosystem | Source | Detection Change Rate | KB Change Rate | Threshold | Result |
|-----------|--------|-----------------------|----------------|-----------|--------|
| microsoft | microsoft-cvrf | 0.0% | 140.0% | 10.0% | **FAIL** |

## KB

| Ecosystem | Source | Baseline KB Keys | Target KB Keys | Added | Removed | Changed | Matched KBs |
|-----------|--------|------------------|----------------|-------|---------|---------|-------------|
| microsoft | microsoft-cvrf | 10 | 10 | 1 | 1 | 2 | 3 |

## Details (FAIL sources)

### microsoft / microsoft-cvrf (140.0%)

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
						Ecosystem: "alma:8",
						Sources: []db.SourceDiff{
							{
								SourceID:           "alma-errata",
								BaselineKeys:       10,
								TargetKeys:         10,
								BaselineCriterions: 50,
								TargetCriterions:   50,
								MatchedCriterions:  50,
								Threshold:          10,
								Pass:               true,
							},
						},
						Pass: true,
					},
					{
						Ecosystem: "microsoft",
						Sources: []db.SourceDiff{
							{
								SourceID:       "microsoft-cvrf",
								BaselineKBKeys: 5,
								TargetKBKeys:   5,
								MatchedKBs:     5,
								Threshold:      10,
								Pass:           true,
							},
						},
						Pass: true,
					},
				},
			},
			wantPass: true,
			wantReport: `# Diff Report: DB

## Summary

**Result**: PASS

| Ecosystem | Source | Detection Change Rate | KB Change Rate | Threshold | Result |
|-----------|--------|-----------------------|----------------|-----------|--------|
| alma:8 | alma-errata | 0.0% | 0.0% | 10.0% | PASS |
| microsoft | microsoft-cvrf | 0.0% | 0.0% | 10.0% | PASS |

## Detection

| Ecosystem | Source | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|--------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
| alma:8 | alma-errata | 10 | 10 | 0 | 0 | 0 | 50 | 50 | 50 |

## KB

| Ecosystem | Source | Baseline KB Keys | Target KB Keys | Added | Removed | Changed | Matched KBs |
|-----------|--------|------------------|----------------|-------|---------|---------|-------------|
| microsoft | microsoft-cvrf | 5 | 5 | 0 | 0 | 0 | 5 |

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
						Ecosystem: "mixed:1",
						Sources: []db.SourceDiff{
							{
								SourceID:            "mixed-source",
								BaselineKeys:        100,
								TargetKeys:          100,
								BaselineCriterions:  10000,
								TargetCriterions:    10050,
								MatchedCriterions:   9950,
								BaselineKBKeys:      5,
								TargetKBKeys:        5,
								MatchedKBs:          3,
								ChangedKBs:          []string{"KB1", "KB2"},
								DetectionChangeRate: 1.5,
								KBChangeRate:        80.0,
								Threshold:           10,
								Pass:                false,
							},
						},
						Pass: false,
					},
				},
			},
			wantPass: false,
			wantReport: `# Diff Report: DB

## Summary

**Result**: **FAIL**

| Ecosystem | Source | Detection Change Rate | KB Change Rate | Threshold | Result |
|-----------|--------|-----------------------|----------------|-----------|--------|
| mixed:1 | mixed-source | 1.5% | 80.0% | 10.0% | **FAIL** |

## Detection

| Ecosystem | Source | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|--------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
| mixed:1 | mixed-source | 100 | 100 | 0 | 0 | 0 | 10000 | 10050 | 9950 |

## KB

| Ecosystem | Source | Baseline KB Keys | Target KB Keys | Added | Removed | Changed | Matched KBs |
|-----------|--------|------------------|----------------|-------|---------|---------|-------------|
| mixed:1 | mixed-source | 5 | 5 | 0 | 0 | 2 | 3 |

## Details (FAIL sources)

### mixed:1 / mixed-source (80.0%)

#### Changed KB IDs (2)

- KB1
- KB2

`,
		},
		{
			name: "override applied",
			args: args{
				diffs: []db.EcosystemDiff{
					{
						Ecosystem: "ubuntu:26.04",
						Sources: []db.SourceDiff{
							{
								SourceID:            "ubuntu-oval",
								BaselineKeys:        100,
								TargetKeys:          100,
								BaselineCriterions:  500,
								TargetCriterions:    500,
								MatchedCriterions:   400,
								Changed:             []string{"CVE-2026-9999"},
								DetectionChangeRate: 40.0,
								Threshold:           50,
								Pass:                true,
							},
						},
						Pass: true,
					},
					{
						Ecosystem: "redhat:9",
						Sources: []db.SourceDiff{
							{
								SourceID:           "redhat-ovalv2",
								BaselineKeys:       50,
								TargetKeys:         50,
								BaselineCriterions: 200,
								TargetCriterions:   200,
								MatchedCriterions:  200,
								Threshold:          10,
								Pass:               true,
							},
						},
						Pass: true,
					},
				},
			},
			wantPass: true,
			wantReport: `# Diff Report: DB

## Summary

**Result**: PASS

| Ecosystem | Source | Detection Change Rate | KB Change Rate | Threshold | Result |
|-----------|--------|-----------------------|----------------|-----------|--------|
| ubuntu:26.04 | ubuntu-oval | 40.0% | 0.0% | 50.0% | PASS |
| redhat:9 | redhat-ovalv2 | 0.0% | 0.0% | 10.0% | PASS |

## Detection

| Ecosystem | Source | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|--------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
| ubuntu:26.04 | ubuntu-oval | 100 | 100 | 0 | 0 | 1 | 500 | 500 | 400 |
| redhat:9 | redhat-ovalv2 | 50 | 50 | 0 | 0 | 0 | 200 | 200 | 200 |

`,
		},
		{
			// Locks the FAIL-first sort tier: a PASS row with a higher rate
			// (held passing by an override) must still sort below a FAIL row
			// whose rate is lower. Pure rate-desc sort would put alpha:1 first.
			name: "FAIL row sorts above higher-rate PASS row",
			args: args{
				diffs: []db.EcosystemDiff{
					{
						Ecosystem: "alpha:1",
						Sources: []db.SourceDiff{
							{
								SourceID:            "src-alpha",
								BaselineKeys:        100,
								TargetKeys:          100,
								BaselineCriterions:  500,
								TargetCriterions:    500,
								MatchedCriterions:   200,
								Changed:             []string{"CVE-2026-AAAA"},
								DetectionChangeRate: 120,
								Threshold:           150,
								Pass:                true,
							},
						},
						Pass: true,
					},
					{
						Ecosystem: "beta:2",
						Sources: []db.SourceDiff{
							{
								SourceID:            "src-beta",
								BaselineKeys:        50,
								TargetKeys:          50,
								BaselineCriterions:  200,
								TargetCriterions:    200,
								MatchedCriterions:   195,
								Changed:             []string{"CVE-2026-BBBB"},
								DetectionChangeRate: 5,
								Threshold:           0,
								Pass:                false,
							},
						},
						Pass: false,
					},
				},
			},
			wantPass: false,
			wantReport: `# Diff Report: DB

## Summary

**Result**: **FAIL**

| Ecosystem | Source | Detection Change Rate | KB Change Rate | Threshold | Result |
|-----------|--------|-----------------------|----------------|-----------|--------|
| beta:2 | src-beta | 5.0% | 0.0% | 0.0% | **FAIL** |
| alpha:1 | src-alpha | 120.0% | 0.0% | 150.0% | PASS |

## Detection

| Ecosystem | Source | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|--------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
| beta:2 | src-beta | 50 | 50 | 0 | 0 | 1 | 200 | 200 | 195 |
| alpha:1 | src-alpha | 100 | 100 | 0 | 0 | 1 | 500 | 500 | 200 |

## Details (FAIL sources)

### beta:2 / src-beta (5.0%)

#### Changed Root IDs (1)

- CVE-2026-BBBB

`,
		},
		{
			// An ecosystem compared without any per-source data must still be
			// visible in the report instead of silently disappearing.
			name: "ecosystem without sources renders a placeholder row",
			args: args{
				diffs: []db.EcosystemDiff{
					{
						Ecosystem: "empty:1",
						Pass:      true,
					},
				},
			},
			wantPass: true,
			wantReport: `# Diff Report: DB

## Summary

**Result**: PASS

| Ecosystem | Source | Detection Change Rate | KB Change Rate | Threshold | Result |
|-----------|--------|-----------------------|----------------|-----------|--------|
| empty:1 | (none) | 0.0% | 0.0% | - | PASS |

`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			gotPass, err := db.GenerateReport(&buf, tt.args.diffs)
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
