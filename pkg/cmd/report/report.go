package report

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

type ReportOptions struct {
	Config string
}

func NewCmdReport() *cobra.Command {
	opts := &ReportOptions{
		Config: "config.json",
	}

	cmd := &cobra.Command{
		Use:   "report (<result path>)",
		Short: "Vuls report vulnerabilities",
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls report
			$ vuls report results
			$ vuls report resutls/2022-11-05T01:08:44+09:00/local/localhost.json
		`),
	}

	cmd.Flags().StringVarP(&opts.Config, "config", "c", "config.json", "vuls config file path")

	return cmd
}
