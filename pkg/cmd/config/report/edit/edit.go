package edit

import (
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

func NewCmd() *cobra.Command {
	options := struct {
		config string
	}{
		config: filepath.Join(utilos.UserConfigDir(), "config.json"),
	}

	cmd := &cobra.Command{
		Use:       "edit",
		Short:     "Vuls Report Config Edit Operation",
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: []string{"stdout", "csv", "xml", "cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-xml", "http", "email", "syslog", "slack", "chatwork", "telegram", "s3", "gcs", "azureblob"},
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}

	cmd.Flags().StringVarP(&options.config, "config", "c", options.config, "vuls config path")

	return cmd
}
