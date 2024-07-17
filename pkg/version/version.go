package version

import "fmt"

var (
	Version  string
	Revision string
)

func String() string {
	return fmt.Sprintf("vuls %s %s\n", Version, Revision)
}
