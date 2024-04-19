package test

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
		Use:   "test",
		Short: "Vuls Detect Config Test Operation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}

	cmd.Flags().StringVarP(&options.config, "config", "c", options.config, "vuls config path")

	return cmd
}
