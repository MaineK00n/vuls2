package detection_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/db/diff/detection"
)

func TestSubtract(t *testing.T) {
	type args struct {
		a []string
		b []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "no diff",
			args: args{
				a: []string{"CVE-2026-0001", "CVE-2026-0002"},
				b: []string{"CVE-2026-0001", "CVE-2026-0002"},
			},
			want: nil,
		},
		{
			name: "a has extras",
			args: args{
				a: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
				b: []string{"CVE-2026-0001"},
			},
			want: []string{"CVE-2026-0002", "CVE-2026-0003"},
		},
		{
			name: "b has extras",
			args: args{
				a: []string{"CVE-2026-0001"},
				b: []string{"CVE-2026-0001", "CVE-2026-0002"},
			},
			want: nil,
		},
		{
			name: "empty a",
			args: args{
				a: nil,
				b: []string{"CVE-2026-0001"},
			},
			want: nil,
		},
		{
			name: "empty b",
			args: args{
				a: []string{"CVE-2026-0001"},
				b: nil,
			},
			want: []string{"CVE-2026-0001"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detection.Subtract(tt.args.a, tt.args.b)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Subtract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestComputeDiffs(t *testing.T) {
	type args struct {
		detections                   map[string]detection.FileDiff
		changeRateThreshold          float64
		changeRateThresholdOverrides map[string]float64
	}
	tests := []struct {
		name string
		args args
		want map[string]detection.FileDiff
	}{
		{
			name: "no change",
			args: args{
				detections: map[string]detection.FileDiff{
					"redhat_9": {
						Name:        "redhat_9",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
					},
				},
				changeRateThreshold: 10,
			},
			want: map[string]detection.FileDiff{
				"redhat_9": {
					Name:        "redhat_9",
					BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
					TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
					ChangeRate:  0,
					Threshold:   10,
					Pass:        true,
				},
			},
		},
		{
			name: "small change within limit",
			args: args{
				detections: map[string]detection.FileDiff{
					"redhat_9": {
						Name: "redhat_9",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
							"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0010"},
						TargetIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
							"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0011"},
					},
				},
				changeRateThreshold: 25,
			},
			want: map[string]detection.FileDiff{
				"redhat_9": {
					Name: "redhat_9",
					BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
						"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0010"},
					TargetIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
						"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0011"},
					Added:      []string{"CVE-2026-0011"},
					Removed:    []string{"CVE-2026-0010"},
					ChangeRate: 20,
					Threshold:  25,
					Pass:       true,
				},
			},
		},
		{
			name: "large change exceeds limit",
			args: args{
				detections: map[string]detection.FileDiff{
					"ubuntu_22.04": {
						Name:        "ubuntu_22.04",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						TargetIDs:   []string{"CVE-2026-0001"},
					},
				},
				changeRateThreshold: 10,
			},
			want: map[string]detection.FileDiff{
				"ubuntu_22.04": {
					Name:        "ubuntu_22.04",
					BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
					TargetIDs:   []string{"CVE-2026-0001"},
					Removed:     []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
					ChangeRate:  75,
					Threshold:   10,
					Pass:        false,
				},
			},
		},
		{
			name: "large addition exceeds limit",
			args: args{
				detections: map[string]detection.FileDiff{
					"ubuntu_22.04": {
						Name:        "ubuntu_22.04",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006"},
					},
				},
				changeRateThreshold: 10,
			},
			want: map[string]detection.FileDiff{
				"ubuntu_22.04": {
					Name:        "ubuntu_22.04",
					BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
					TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006"},
					Added:       []string{"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006"},
					ChangeRate:  200,
					Threshold:   10,
					Pass:        false,
				},
			},
		},
		{
			name: "empty baseline triggers 100% change",
			args: args{
				detections: map[string]detection.FileDiff{
					"redhat_9": {
						Name:        "redhat_9",
						BaselineIDs: []string{},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
					},
				},
				changeRateThreshold: 10,
			},
			want: map[string]detection.FileDiff{
				"redhat_9": {
					Name:        "redhat_9",
					BaselineIDs: []string{},
					TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
					Added:       []string{"CVE-2026-0001", "CVE-2026-0002"},
					ChangeRate:  100,
					Threshold:   10,
					Pass:        false,
				},
			},
		},
		{
			name: "both empty avoids zero division",
			args: args{
				detections: map[string]detection.FileDiff{
					"redhat_9": {
						Name:        "redhat_9",
						BaselineIDs: []string{},
						TargetIDs:   []string{},
					},
				},
				changeRateThreshold: 10,
			},
			want: map[string]detection.FileDiff{
				"redhat_9": {
					Name:        "redhat_9",
					BaselineIDs: []string{},
					TargetIDs:   []string{},
					ChangeRate:  0,
					Threshold:   10,
					Pass:        true,
				},
			},
		},
		{
			name: "target all removed",
			args: args{
				detections: map[string]detection.FileDiff{
					"redhat_9": {
						Name:        "redhat_9",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
					},
					"ubuntu_22.04": {
						Name:        "ubuntu_22.04",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
						TargetIDs:   nil,
					},
				},
				changeRateThreshold: 10,
			},
			want: map[string]detection.FileDiff{
				"redhat_9": {
					Name:        "redhat_9",
					BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
					TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
					ChangeRate:  0,
					Threshold:   10,
					Pass:        true,
				},
				"ubuntu_22.04": {
					Name:        "ubuntu_22.04",
					BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
					Removed:     []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
					ChangeRate:  100,
					Threshold:   10,
					Pass:        false,
				},
			},
		},
		{
			name: "multiple files mixed",
			args: args{
				detections: map[string]detection.FileDiff{
					"redhat_9": {
						Name:        "redhat_9",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
					},
					"ubuntu_22.04": {
						Name:        "ubuntu_22.04",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						TargetIDs:   []string{"CVE-2026-0001"},
					},
				},
				changeRateThreshold: 10,
			},
			want: map[string]detection.FileDiff{
				"redhat_9": {
					Name:        "redhat_9",
					BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
					TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
					ChangeRate:  0,
					Threshold:   10,
					Pass:        true,
				},
				"ubuntu_22.04": {
					Name:        "ubuntu_22.04",
					BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
					TargetIDs:   []string{"CVE-2026-0001"},
					Removed:     []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
					ChangeRate:  75,
					Threshold:   10,
					Pass:        false,
				},
			},
		},
		{
			name: "override lifts a single file above default threshold",
			args: args{
				detections: map[string]detection.FileDiff{
					"debian_13": {
						Name:        "debian_13",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
					},
					"redhat_9": {
						Name:        "redhat_9",
						BaselineIDs: []string{"CVE-2026-0001"},
						TargetIDs:   []string{"CVE-2026-0001"},
					},
				},
				changeRateThreshold:          10,
				changeRateThresholdOverrides: map[string]float64{"debian_13": 80},
			},
			want: map[string]detection.FileDiff{
				"debian_13": {
					Name:        "debian_13",
					BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
					TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
					Added:       []string{"CVE-2026-0003"},
					ChangeRate:  50,
					Threshold:   80,
					Pass:        true,
				},
				"redhat_9": {
					Name:        "redhat_9",
					BaselineIDs: []string{"CVE-2026-0001"},
					TargetIDs:   []string{"CVE-2026-0001"},
					ChangeRate:  0,
					Threshold:   10,
					Pass:        true,
				},
			},
		},
		{
			name: "override below rate still fails",
			args: args{
				detections: map[string]detection.FileDiff{
					"debian_13": {
						Name:        "debian_13",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
					},
				},
				changeRateThreshold:          10,
				changeRateThresholdOverrides: map[string]float64{"debian_13": 30},
			},
			want: map[string]detection.FileDiff{
				"debian_13": {
					Name:        "debian_13",
					BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
					TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
					Added:       []string{"CVE-2026-0003"},
					ChangeRate:  50,
					Threshold:   30,
					Pass:        false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detection.ComputeDiffs(tt.args.detections, tt.args.changeRateThreshold, tt.args.changeRateThresholdOverrides)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ComputeDiffs() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGenerateReport(t *testing.T) {
	type args struct {
		diffs map[string]detection.FileDiff
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
				diffs: map[string]detection.FileDiff{
					"redhat_9": {
						Name:        "redhat_9",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
						ChangeRate:  0,
						Threshold:   10,
						Pass:        true,
					},
					"ubuntu_22.04": {
						Name:        "ubuntu_22.04",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						TargetIDs:   []string{"CVE-2026-0001"},
						Removed:     []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						ChangeRate:  75.0,
						Threshold:   10,
						Pass:        false,
					},
				},
			},
			wantPass: false,
			wantReport: `# Diff Report: Detection

## Summary

**Result**: **FAIL**

| Name | Baseline | Target | Added | Removed | Change Rate | Threshold | Result |
|------|----------|--------|-------|---------|-------------|-----------|--------|
| ubuntu_22.04 | 4 | 1 | 0 | 3 | 75.0% | 10.0% | **FAIL** |
| redhat_9 | 2 | 2 | 0 | 0 | 0.0% | 10.0% | PASS |

## Details (FAIL files)

### ubuntu_22.04 (75.0%)

#### Removed IDs (3)

- CVE-2026-0002
- CVE-2026-0003
- CVE-2026-0004

`,
		},
		{
			name: "all pass",
			args: args{
				diffs: map[string]detection.FileDiff{
					"redhat_9": {
						Name:        "redhat_9",
						BaselineIDs: []string{"CVE-2026-0001"},
						TargetIDs:   []string{"CVE-2026-0001"},
						ChangeRate:  0,
						Threshold:   10,
						Pass:        true,
					},
				},
			},
			wantPass: true,
			wantReport: `# Diff Report: Detection

## Summary

**Result**: PASS

| Name | Baseline | Target | Added | Removed | Change Rate | Threshold | Result |
|------|----------|--------|-------|---------|-------------|-----------|--------|
| redhat_9 | 1 | 1 | 0 | 0 | 0.0% | 10.0% | PASS |

`,
		},
		{
			name: "override applied",
			args: args{
				diffs: map[string]detection.FileDiff{
					"debian_13": {
						Name:        "debian_13",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
						Added:       []string{"CVE-2026-0003"},
						ChangeRate:  50,
						Threshold:   80,
						Pass:        true,
					},
					"redhat_9": {
						Name:        "redhat_9",
						BaselineIDs: []string{"CVE-2026-0001"},
						TargetIDs:   []string{"CVE-2026-0001"},
						ChangeRate:  0,
						Threshold:   10,
						Pass:        true,
					},
				},
			},
			wantPass: true,
			wantReport: `# Diff Report: Detection

## Summary

**Result**: PASS

| Name | Baseline | Target | Added | Removed | Change Rate | Threshold | Result |
|------|----------|--------|-------|---------|-------------|-----------|--------|
| debian_13 | 2 | 3 | 1 | 0 | 50.0% | 80.0% | PASS |
| redhat_9 | 1 | 1 | 0 | 0 | 0.0% | 10.0% | PASS |

`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			gotPass, err := detection.GenerateReport(&buf, tt.args.diffs)
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

func TestDiff(t *testing.T) {
	// Prepare a scan results directory with two dummy JSON files.
	scanDir := t.TempDir()
	for _, name := range []string{"redhat_9.json", "ubuntu_2204.json"} {
		if err := os.WriteFile(filepath.Join(scanDir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	fakeDetect := func(_, _, _, _ string, files map[string]string) (map[string]detection.FileDiff, error) {
		result := make(map[string]detection.FileDiff, len(files))
		for name := range files {
			switch name {
			case "redhat_9":
				result[name] = detection.FileDiff{
					Name:        name,
					BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
					TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
				}
			case "ubuntu_2204":
				result[name] = detection.FileDiff{
					Name:        name,
					BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
					TargetIDs:   []string{"CVE-2026-0001"},
				}
			}
		}
		return result, nil
	}

	fakeDetectErr := func(_, _, _, _ string, _ map[string]string) (map[string]detection.FileDiff, error) {
		return nil, errors.New("vuls0 crashed")
	}

	emptyDir := t.TempDir()

	type args struct {
		dir                 string
		detectFunc          detection.DetectFunc
		changeRateThreshold float64
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "fail on exceeded change rate",
			args: args{
				dir:                 scanDir,
				detectFunc:          fakeDetect,
				changeRateThreshold: 10,
			},
			wantErr: true,
		},
		{
			name: "pass within threshold",
			args: args{
				dir:                 scanDir,
				detectFunc:          fakeDetect,
				changeRateThreshold: 100,
			},
			wantErr: false,
		},
		{
			name: "detect error propagated",
			args: args{
				dir:                 scanDir,
				detectFunc:          fakeDetectErr,
				changeRateThreshold: 10,
			},
			wantErr: true,
		},
		{
			name: "no scan results error",
			args: args{
				dir:                 emptyDir,
				detectFunc:          fakeDetect,
				changeRateThreshold: 10,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := detection.Diff(
				tt.args.dir, "baseline.db", "vuls0", "target.db", "vuls0",
				detection.WithChangeRateThreshold(tt.args.changeRateThreshold),
				detection.WithWriter(&bytes.Buffer{}),
				detection.WithDetectFunc(tt.args.detectFunc),
			)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Diff() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
