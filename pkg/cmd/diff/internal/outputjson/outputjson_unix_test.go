//go:build unix

package outputjson_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/outputjson"
)

func TestClearRefusesFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "out.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := outputjson.Clear(fifo); err == nil {
		t.Fatal("Clear() error = nil, want refusal for a FIFO")
	}
	if _, err := os.Lstat(fifo); err != nil {
		t.Fatalf("Clear() removed the FIFO: %v", err)
	}
}
