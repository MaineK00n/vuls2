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
		Use:   "push <repository>[:<tag>] <Zstandard compressed dbpath>",
		Short: "Push vuls db to repository",
		Long: heredoc.Doc(`
		Push a Zstandard-compressed vuls db to an OCI registry.

		If the reference is given as "<repository>:<tag>" the manifest is
		tagged. If only "<repository>" is given, the manifest is pushed
		without a tag and is only reachable by its digest. Digest
		references ("<repository>@<digest>") are rejected.

		The pushed manifest's digest is written to stdout (as a single
		"sha256:..." line), so callers can capture it directly, e.g.
		"digest=$(vuls db push ghcr.io/... vuls.db.zst)".
		`),
		Example: heredoc.Doc(`
		$ vuls db push ghcr.io/mainek00n/vuls2:latest vuls.db.zst
		$ vuls db push ghcr.io/mainek00n/vuls2 vuls.db.zst
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
