package push

import (
	"os"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	db "github.com/MaineK00n/vuls2/pkg/db/push"
)

func NewCmd() *cobra.Command {
	options := &struct {
		force       bool
		token       string
		annotations []string
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
		$ vuls db push --annotation io.vuls.db.branch=nightly --annotation org.opencontainers.image.revision=0123abc ghcr.io/mainek00n/vuls2 vuls.db.zst
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			annotations, err := parseAnnotations(options.annotations)
			if err != nil {
				return errors.Wrap(err, "parse annotations")
			}
			if err := db.Push(args[0], args[1], options.token, db.WithForce(options.force), db.WithAnnotations(annotations)); err != nil {
				return errors.Wrap(err, "db push")
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&options.force, "force", "f", options.force, "overwrite existing tag")
	cmd.Flags().StringVarP(&options.token, "token", "", options.token, "specify GitHub token")
	cmd.Flags().StringArrayVarP(&options.annotations, "annotation", "", nil, "manifest annotation in <key>=<value> format (repeatable)")

	return cmd
}

func parseAnnotations(ss []string) (map[string]string, error) {
	if len(ss) == 0 {
		return nil, nil
	}

	annotations := make(map[string]string, len(ss))
	for _, s := range ss {
		k, v, found := strings.Cut(s, "=")
		if !found || k == "" {
			return nil, errors.Errorf("unexpected annotation format. expected: %q, actual: %q", "<key>=<value>", s)
		}
		if _, ok := annotations[k]; ok {
			return nil, errors.Errorf("duplicate annotation key %q", k)
		}
		annotations[k] = v
	}

	return annotations, nil
}
