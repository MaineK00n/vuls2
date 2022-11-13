package init

import (
	"os"
	"text/template"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewCmdInit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "generate vuls config template",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return generateConfigTemplate()
		},
		Example: heredoc.Doc(`
			$ vuls config init > config.json
		`),
	}

	return cmd
}

func generateConfigTemplate() error {
	pwd, err := os.Getwd()
	if err != nil {
		pwd = os.TempDir()
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/home/vuls"
	}

	create := func(name, t string) *template.Template {
		return template.Must(template.New(name).Parse(t))
	}

	t := create("config template",
		`{
	"server": {
		"listen": "127.0.0.1:5515",
		"path": "{{.pwd}}/vuls.db"
	},
	"hosts": {
		"local": {
			"type": "local",
			"scan": {
				"ospkg": {
					"root": false
				}
			},
			"detect": {
				"path": "{{.pwd}}/vuls.db",
				"result_dir": "{{.pwd}}/results"
			}
		},
		"remote": {
			"type": "remote",
			"host": "127.0.0.1",
			"port": "22",
			"user": "vuls",
			"ssh_config": "{{.home}}/.ssh/config",
			"ssh_key": "{{.home}}/.ssh/id_rsa",
			"scan": {
				"ospkg": {
					"root": false
				}
			},
			"detect": {
				"path": "{{.pwd}}/vuls.db",
				"result_dir": "{{.pwd}}/results"
			}
		},
		"cpe": {
			"type": "local",
			"scan": {
				"cpe": [
					{
						"cpe": "cpe:2.3:a:apache:log4j:2.3:*:*:*:*:*:*:*"
					}
				]
			},
			"detect": {
				"path": "{{.pwd}}/vuls.db",
				"result_dir": "{{.pwd}}/results"
			}
		}
	}
}
`)

	if err := t.Execute(os.Stdout, map[string]string{"pwd": pwd, "home": home}); err != nil {
		return errors.Wrap(err, "output config template")
	}
	return nil
}
