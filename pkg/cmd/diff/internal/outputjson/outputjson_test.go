package outputjson_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/outputjson"
)

func TestCreate(t *testing.T) {
	t.Run("creates the file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "diff.json")
		f, err := outputjson.Create(path)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if _, err := f.WriteString(`{"pass":true}`); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `{"pass":true}` {
			t.Errorf("content = %q", got)
		}
	})
	t.Run("truncates a previous run's file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "diff.json")
		if err := os.WriteFile(path, []byte(`{"stale":true,"rows":[1,2,3]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := outputjson.Create(path)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("Create() left previous content %q, want empty", got)
		}
	})
	t.Run("empty path yields no file", func(t *testing.T) {
		f, err := outputjson.Create("")
		if err != nil || f != nil {
			t.Fatalf("Create(\"\") = %v, %v; want nil, nil", f, err)
		}
	})
	t.Run("directory is refused and kept", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := outputjson.Create(dir); err == nil {
			t.Fatal("Create() error = nil, want refusal for a directory")
		}
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			t.Fatalf("Create() disturbed the directory (stat err = %v)", err)
		}
	})
	t.Run("symlink is refused and its target kept", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := outputjson.Create(link); err == nil {
			t.Fatal("Create() error = nil, want refusal for a symlink")
		}
		got, err := os.ReadFile(target)
		if err != nil || string(got) != `{}` {
			t.Fatalf("Create() disturbed the symlink target: %q, %v", got, err)
		}
	})
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	baseline := mk("baseline.db")
	target := mk("target.db")
	scanDir := filepath.Join(dir, "scan-results")
	if err := os.Mkdir(scanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mk("scan-results/rhel_10.json")
	link := filepath.Join(dir, "alias.db")
	if err := os.Symlink(baseline, link); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(dir, "scan-alias")
	if err := os.Symlink(scanDir, dirLink); err != nil {
		t.Fatal(err)
	}
	hardLink := filepath.Join(dir, "hardlink.db")
	if err := os.Link(target, hardLink); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		inputs  []string
		wantErr bool
	}{
		{name: "empty path", path: "", inputs: []string{baseline}},
		{name: "unrelated new file", path: filepath.Join(dir, "diff.json"), inputs: []string{baseline, target, scanDir}},
		{name: "same file", path: baseline, inputs: []string{baseline, target}, wantErr: true},
		{name: "symlink alias of an input", path: link, inputs: []string{baseline}, wantErr: true},
		{name: "input given through a symlink", path: baseline, inputs: []string{link}, wantErr: true},
		{name: "hard link of an input (filesystem identity)", path: hardLink, inputs: []string{target}, wantErr: true},
		{name: "file inside input directory", path: filepath.Join(scanDir, "rhel_10.json"), inputs: []string{scanDir}, wantErr: true},
		{name: "new file inside input directory", path: filepath.Join(scanDir, "diff.json"), inputs: []string{scanDir}, wantErr: true},
		{name: "new file inside symlinked input directory", path: filepath.Join(dirLink, "diff.json"), inputs: []string{scanDir}, wantErr: true},
		{name: "sibling with the directory name as prefix", path: filepath.Join(dir, "scan-results.json"), inputs: []string{scanDir}},
		{name: "input directory is the filesystem root", path: filepath.Join(string(filepath.Separator), "vuls-diff-output-json-test.json"), inputs: []string{string(filepath.Separator)}, wantErr: true},
		{name: "output equals the input directory itself", path: scanDir, inputs: []string{scanDir}, wantErr: true},
		{name: "nonexistent input is ignored", path: filepath.Join(dir, "diff.json"), inputs: []string{filepath.Join(dir, "missing.db")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := outputjson.Validate(tt.path, tt.inputs...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
