package edit

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
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
		Use:   "edit",
		Short: "Vuls Host Config Edit Operation",
		Args:  cobra.ExactArgs(1),
		Example: heredoc.Doc(`
		$ vuls config edit 2f687768-abbf-287e-b232-892edcf0d768
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}

	cmd.Flags().StringVarP(&options.config, "config", "c", options.config, "vuls config path")

	return cmd
}
