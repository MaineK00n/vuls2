//go:build unix

package outputjson_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/outputjson"
)

func TestCreateRefusesFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "out.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	// Opening a FIFO for writing would block until a reader shows up, so
	// Create must refuse it from the Lstat alone.
	if _, err := outputjson.Create(fifo); err == nil {
		t.Fatal("Create() error = nil, want refusal for a FIFO")
	}
	if _, err := os.Lstat(fifo); err != nil {
		t.Fatalf("Create() removed the FIFO: %v", err)
	}
}
