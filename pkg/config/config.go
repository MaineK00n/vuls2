package config

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"

	"github.com/pkg/errors"
)

func Open(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	var src Config
	if err := json.NewDecoder(f).Decode(&src); err != nil {
		return Config{}, errors.Wrap(err, "decode json")
	}

	u, err := user.Current()
	if err != nil {
		return Config{}, errors.Wrap(err, "get current user")
	}

	pwd, err := os.Getwd()
	if err != nil {
		return Config{}, errors.Wrap(err, "get working directory")
	}

	config := Config{Server: src.Server, Hosts: map[string]Host{}}
	for n, h := range src.Hosts {
		c := Host{
			Type:      h.Type,
			Host:      h.Host,
			Port:      h.Port,
			User:      h.User,
			SSHConfig: h.SSHConfig,
			SSHKey:    h.SSHKey,
			Scan:      src.Scan,
			Detect:    src.Detect,
			Report:    src.Report,
		}
		if h.User == nil {
			h.User = &u.Name
		}

		if h.Scan != nil {
			c.Scan = h.Scan
		}
		if c.Scan != nil && c.Scan.ResultDir == "" {
			c.Scan.ResultDir = filepath.Join(pwd, "results")
		}
		if c.Scan != nil && c.Scan.LogDir == "" {
			c.Scan.LogDir = "/var/log/vuls"
		}

		if h.Detect != nil {
			c.Detect = h.Detect
		}
		if c.Detect != nil && c.Detect.ResultDir == "" {
			c.Detect.ResultDir = filepath.Join(pwd, "results")
		}
		if c.Detect != nil && c.Detect.LogDir == "" {
			c.Detect.LogDir = "/var/log/vuls"
		}

		if h.Report != nil {
			c.Report = h.Report
		}
		if c.Report != nil && c.Report.ResultDir == "" {
			c.Report.ResultDir = filepath.Join(pwd, "results")
		}
		if c.Report != nil && c.Report.LogDir == "" {
			c.Report.LogDir = "/var/log/vuls"
		}

		config.Hosts[n] = c
	}

	return config, nil
}
