package create

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

func NewCmdCreate() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create Vuls DB",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls db create https://github.com/vulsio/vuls-data.git
			$ vuls db create /home/MaineK00n/.cache/vuls
		`),
	}

	return cmd
}
