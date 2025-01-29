package flag

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type DBType string

const (
	DBTypeBoltDB     DBType = "boltdb"
	DBTypeRedis      DBType = "redis"
	DBTypeSQLite3    DBType = "sqlite3"
	DBTypeMySQL      DBType = "mysql"
	DBTypePostgreSQL DBType = "postgres"
	DBTypePebble     DBType = "pebble"
)

func (t *DBType) String() string {
	return string(*t)
}

func (t *DBType) Set(v string) error {
	switch v {
	case "boltdb", "redis", "sqlite3", "mysql", "postgres", "pebble":
		*t = DBType(v)
		return nil
	default:
		return errors.Errorf("unexpected dbtype. accepts: %q, actual: %q", []DBType{DBTypeBoltDB, DBTypeRedis, DBTypeSQLite3, DBTypeMySQL, DBTypePostgreSQL}, v)
	}
}

func (t *DBType) Type() string {
	return "DBType"
}

func DBTypeCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{string(DBTypeBoltDB), string(DBTypeRedis), string(DBTypeSQLite3), string(DBTypeMySQL), string(DBTypePostgreSQL), string(DBTypePebble)}, cobra.ShellCompDirectiveDefault
}
