package fetch

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

func NewCmdFetch() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch Vuls DB",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls db fetch
			$ vuls db fetch ghcr.io/vuls/db
		`),
	}

	return cmd
}
