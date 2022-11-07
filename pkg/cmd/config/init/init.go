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
	"scan": {
		"ospkg": {
			"root": false,
			"offline": false
		},
		"langpkg": {},
		"lockfile": {
			"find": false,
			"path": []
		},
		"wordpress": {
			"root": "",
			"path": "",
			"user": "",
			"doc_root": ""
		},
		"cpe": [
			{
				"cpe": "",
				"running_on": ""
			}
		],
		"sbom": [],
		"port": {
			"type": "builtin", // ["builtin", "nmap"]
			"nmap": {}
		},
		"timeout_unit": 300,
		"timeout_scan": 7200,
		"result_dir": "{{.pwd}}/results",
		"log_dir": "/var/log/vuls",
		"debug": false
	},
	"detect": {
		"path": "{{.pwd}}/vuls.db",
		"cpe": {
			"match": "strict" // "strict", "standard", "lax"
		},
		"result_dir": "{{.pwd}}/results",
		"log_dir": "/var/log/vuls",
		"debug": false
	},
	"report": {
		"stdout": "oneline", // ["oneline", "list", "full"]
		"localfile": [
			"json",
			"xml",
			"csv",
			"cyclonedx-json",
			"cyclonedx-xml"
		],
		"aws": {},
		"gcp": {},
		"azure": {},
		"syslog": {},
		"http": {},
		"email": {},
		"slack": {},
		"chatwork": {},
		"googlechat": {},
		"telegram": {},
		"ignore": {
			"cvss-under": 0,
			"id": [],
			"package": []
		},
		"result_dir": "{{.pwd}}/results",
		"log_dir": "/var/log/vuls",
		"debug": false
	},
	"server": {
		"listen": "127.0.0.1:5515",
		"path": "{{.pwd}}/vuls.db",
		"scan": {
			"compress": "gzip" // ["gzip", "bzip2", "xz"]
		},
		"detect": {
			"compress": "gzip" // ["gzip", "bzip2", "xz"]
		},
		"report": {
			"format": "json", // ["json", "xml", "csv", "cyclonedx-json", "cyclonedx-xml"],
			"compress": "gzip" // ["gzip", "bzip2", "xz"]
	},
		"log_dir": "/var/log/vuls",
		"debug": false
	},
	"hosts": {
		"local": {
			"type": "local"
		},
		"remote": {
			"type": "remote", // [local, remote, ssh-config, cidr, sbom, docker, lxd, lxc]
			"host": "127.0.0.1", // local: none, remote: ip address, ssh-config: host name, cidr: cidr range, sbom: file path, docker: ${running} or container id, name, lxd: ${running} or container id, name , lxc: ${running} or container id, name
			"port": "22", // local: none, remote: port, ssh-config: none, cidr: port, sbom: none, docker: none, lxd: none, lxc: none
			"user": "vuls", // local: none, remote: required, ssh-config: none, cidr: required, sbom: none, docker: none, lxd: none, lxc: none
			"ssh_config": "{{.home}}/.ssh/config", // local: none, remote: optional, ssh-config: required, cidr: optional, sbom: none, docker: none, lxd: none, lxc: none
			"ssh_key": "{{.home}}/.ssh/id_rsa", // local: none, remote: ssh key path, ssh-config: none, cidr: ssh key path, sbom: none, docker: none, lxd: none, lxc: none
			"scan": {},
			"detect": {},
			"report": {}
		}
	}
}
`)

	if err := t.Execute(os.Stdout, map[string]string{"pwd": pwd, "home": home}); err != nil {
		return errors.Wrap(err, "output config template")
	}
	return nil
}
