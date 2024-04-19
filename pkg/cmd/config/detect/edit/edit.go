package edit

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/config/detect"
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
		Short:     "Vuls Detect Config Edit Operation",
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: []string{"vulndb", "wordpress"},
		Example: heredoc.Doc(`
		$ vuls config detect edit vulndb
		$ vuls config detect edit wordpress
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := detect.Edit(detect.WithConfig(options.config)); err != nil {
				return errors.Wrap(err, "edit detect config")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.config, "config", "c", options.config, "vuls config path")

	return cmd
}
