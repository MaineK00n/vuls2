package remove

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
		Use:   "remove ([<uuid>])",
		Short: "Vuls Host Config Remove Operation",
		Args:  cobra.MinimumNArgs(1),
		Example: heredoc.Doc(`
		$ vuls config remove 2f687768-abbf-287e-b232-892edcf0d768
		$ vuls config remove 2f687768-abbf-287e-b232-892edcf0d768 0084118a-4b0f-fb97-ee67-643dec07d5ff
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}

	cmd.Flags().StringVarP(&options.config, "config", "c", options.config, "vuls config path")

	return cmd
}
