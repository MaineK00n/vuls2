package flag

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type DBType string

const (
	DBTypeBoltDB DBType = "boltdb"
)

func (t *DBType) String() string {
	return string(*t)
}

func (t *DBType) Set(v string) error {
	switch v {
	case "boltdb":
		*t = DBType(v)
		return nil
	default:
		return errors.Errorf("unexpected dbtype. accepts: %q, actual: %q", []DBType{DBTypeBoltDB}, v)
	}
}

func (t *DBType) Type() string {
	return "DBType"
}

func DBTypeCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{string(DBTypeBoltDB)}, cobra.ShellCompDirectiveDefault
}
