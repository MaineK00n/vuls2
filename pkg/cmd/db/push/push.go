package push

import (
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	db "github.com/MaineK00n/vuls2/pkg/db/push"
)

func NewCmd() *cobra.Command {
	options := &struct {
		force bool
		token string
	}{
		force: false,
		token: os.Getenv("GITHUB_TOKEN"),
	}

	cmd := &cobra.Command{
		Use:   "push <repository> <Zstandard compressed dbpath>",
		Short: "Push vuls db to repository",
		Example: heredoc.Doc(`
		$ vuls db push ghcr.io/mainek00n/vuls2:latest vuls.db.zst
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := db.Push(args[0], args[1], options.token, db.WithForce(options.force)); err != nil {
				return errors.Wrap(err, "db push")
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&options.force, "force", "f", options.force, "overwrite existing tag")
	cmd.Flags().StringVarP(&options.token, "token", "", options.token, "specify GitHub token")

	return cmd
}
