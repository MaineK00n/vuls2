package version

import (
	"fmt"
	"runtime/debug"
)

var (
	Version  string
	Revision string
)

func String() string {
	if Version != "" && Revision != "" {
		return fmt.Sprintf("vuls %s %s", Version, Revision)
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		return fmt.Sprintf("vuls %s", info.Main.Version)
	}

	return fmt.Sprintf("vuls %s", "(unknown)")
}
