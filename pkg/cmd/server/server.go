package server

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

type Serveroptions struct {
	Config string
}

func NewCmdServer() *cobra.Command {
	opts := &Serveroptions{
		Config: "config.json",
	}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Vuls start server mode",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls server
		`),
	}

	cmd.Flags().StringVarP(&opts.Config, "config", "c", "config.json", "vuls config file path")

	return cmd
}
