package init

import (
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	config "github.com/MaineK00n/vuls2/pkg/config/init"
)

func NewCmd() *cobra.Command {
	options := struct {
		config string
	}{
		config: func() string {
			d, err := os.UserConfigDir()
			if err != nil {
				return "config.json"
			}
			return filepath.Join(d, "vuls", "config.json")
		}(),
	}

	cmd := &cobra.Command{
		Use:   "init",
		Short: "initialize vuls config",
		Example: heredoc.Doc(`
		$ vuls config init
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := config.Init(config.WithConfig(options.config)); err != nil {
				return errors.Wrap(err, "config init")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.config, "config", "C", options.config, "use config.json path")

	return cmd
}
