package detect

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

type DetectOptions struct {
	Config string
}

func NewCmdDetect() *cobra.Command {
	opts := &DetectOptions{
		Config: "config.json",
	}

	cmd := &cobra.Command{
		Use:   "detect ([\"host\"])",
		Short: "Vuls detect vulnerabilities",
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls detect
			$ vuls detect host
		`),
	}

	cmd.Flags().StringVarP(&opts.Config, "config", "c", "config.json", "vuls config file path")

	return cmd
}
