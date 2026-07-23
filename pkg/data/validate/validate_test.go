package validate

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestValidate(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "data", "2024"), 0o755); err != nil {
		t.Fatal(err)
	}

	// clean: detection condition (cpe, vulnerable) referenced by the vulnerability segment
	if err := os.WriteFile(filepath.Join(root, "data", "2024", "CVE-2024-0001.json"), []byte(`{
		"id": "CVE-2024-0001",
		"vulnerabilities": [
			{
				"content": {"id": "CVE-2024-0001"},
				"segments": [{"ecosystem": "cpe", "tag": "vulnerable"}]
			}
		],
		"detections": [
			{
				"ecosystem": "cpe",
				"conditions": [
					{
						"criteria": {
							"operator": "OR",
							"criterions": [
								{
									"type": "cpe",
									"cpe": {
										"vulnerable": true,
										"cpe": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
										"cpe_matches": ["cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"]
									}
								}
							]
						},
						"tag": "vulnerable"
					}
				]
			}
		]
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// broken: pvp mismatch in cpe_matches + orphan segment on the advisory
	if err := os.WriteFile(filepath.Join(root, "data", "2024", "CVE-2024-0002.json"), []byte(`{
		"id": "CVE-2024-0002",
		"advisories": [
			{
				"content": {"id": "ADV-2024-0002"},
				"segments": [{"ecosystem": "cpe", "tag": "orphan"}]
			}
		],
		"detections": [
			{
				"ecosystem": "cpe",
				"conditions": [
					{
						"criteria": {
							"operator": "OR",
							"criterions": [
								{
									"type": "cpe",
									"cpe": {
										"vulnerable": true,
										"cpe": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
										"cpe_matches": ["cpe:2.3:a:vendor:other:1.0.0:*:*:*:*:*:*:*"]
									}
								}
							]
						},
						"tag": "vulnerable"
					}
				]
			}
		]
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("all checks", func(t *testing.T) {
		findings, err := Validate(root)
		if err != nil {
			t.Fatalf("Validate() error = %v", err)
		}

		var got []struct {
			path  string
			check string
		}
		for _, f := range findings {
			got = append(got, struct {
				path  string
				check string
			}{path: f.Path, check: f.Check})
		}
		want := []struct {
			path  string
			check string
		}{
			{path: "data/2024/CVE-2024-0002.json", check: "cpe-pvp"},
			{path: "data/2024/CVE-2024-0002.json", check: "orphan-segment"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Validate() = %+v, want %+v", got, want)
		}
	})

	t.Run("selected check only", func(t *testing.T) {
		findings, err := Validate(root, WithChecks([]string{"orphan-segment"}))
		if err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if len(findings) != 1 || findings[0].Check != "orphan-segment" || findings[0].ID != "CVE-2024-0002" {
			t.Errorf("Validate() = %+v, want 1 orphan-segment finding for CVE-2024-0002", findings)
		}
	})

	t.Run("unknown check", func(t *testing.T) {
		if _, err := Validate(root, WithChecks([]string{"no-such-check"})); err == nil {
			t.Error("Validate() error = nil, want error")
		}
	})

	t.Run("no data directory", func(t *testing.T) {
		findings, err := Validate(t.TempDir())
		if err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("Validate() = %+v, want no findings", findings)
		}
	})

	t.Run("root does not exist", func(t *testing.T) {
		if _, err := Validate(filepath.Join(root, "no-such-dir")); err == nil {
			t.Error("Validate() error = nil, want error")
		}
	})
}

func TestValidateRootIsFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(f); err == nil {
		t.Error("Validate() error = nil, want error for non-directory root")
	}
}

func TestValidateDuplicateChecks(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data", "CVE-2024-0003.json"), []byte(`{
		"id": "CVE-2024-0003",
		"vulnerabilities": [
			{"content": {"id": "CVE-2024-0003"}, "segments": [{"ecosystem": "cpe", "tag": "orphan"}]}
		]
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := Validate(root, WithChecks([]string{"orphan-segment", "orphan-segment"}))
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("Validate() = %d finding(s), want 1 (duplicate check names must be deduplicated)", len(findings))
	}
}
