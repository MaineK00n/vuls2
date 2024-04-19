package os

import (
	"os"
	"path/filepath"
)

func UserConfigDir() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return "."
	}
	return filepath.Join(d, "vuls")
}

func UserCacheDir() string {
	d, err := os.UserCacheDir()
	if err != nil {
		return "."
	}
	return filepath.Join(d, "vuls")
}
