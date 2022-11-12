package types

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/knqyf263/go-cpe/common"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/config"
	"github.com/MaineK00n/vuls2/pkg/db/types"
)

type Host struct {
	Name    string
	Family  string
	Release string

	ScannedAt       time.Time
	ScannedVersion  string
	ScannedRevision string

	ReportedVersion  string
	ReportedRevision string
	Error            string

	Packages    Packages
	ScannedCves []VulnInfo

	Config Config
}

func (h *Host) Exec(ctx context.Context, cmd string, sudo bool) (int, string, string, error) {
	if sudo {
		cmd = fmt.Sprintf("sudo -S %s", cmd)
	}
	switch h.Config.Type {
	case "local":
		execCmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
		var stdoutBuf, stderrBuf bytes.Buffer
		execCmd.Stdout = &stdoutBuf
		execCmd.Stderr = &stderrBuf
		if err := execCmd.Run(); err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				if s, ok := e.Sys().(syscall.WaitStatus); ok {
					return s.ExitStatus(), stdoutBuf.String(), stderrBuf.String(), nil
				} else {
					return 998, stdoutBuf.String(), stderrBuf.String(), nil
				}
			} else {
				return 999, stdoutBuf.String(), stderrBuf.String(), nil
			}
		} else {
			return 0, stdoutBuf.String(), stderrBuf.String(), nil
		}
	case "remote":
		sshBinPath, err := exec.LookPath("ssh")
		if err != nil {
			return 0, "", "", errors.Wrap(err, "look path to ssh")
		}

		args := []string{"-tt"}

		home, err := os.UserHomeDir()
		if err != nil {
			return 0, "", "", errors.Wrap(err, "find %s home directory")
		}
		args = append(args,
			"-o", "StrictHostKeyChecking=yes",
			"-o", "LogLevel=quiet",
			"-o", "ConnectionAttempts=3",
			"-o", "ConnectTimeout=10",
			"-o", "ControlMaster=auto",
			"-o", fmt.Sprintf("ControlPath=%s", filepath.Join(home, ".vuls", fmt.Sprintf("controlmaster-%%r-%s.%%p", h.Name))),
			"-o", "Controlpersist=10m",
			"-l", *h.Config.User,
		)
		if h.Config.Port != nil {
			args = append(args, "-p", *h.Config.Port)
		}
		if h.Config.SSHKey != nil {
			args = append(args, "-i", *h.Config.SSHKey, "-o", "PasswordAuthentication=no")
		}
		args = append(args, *h.Config.Host, fmt.Sprintf("stty cols 1000; %s", cmd))

		execCmd := exec.CommandContext(ctx, sshBinPath, args...)
		var stdoutBuf, stderrBuf bytes.Buffer
		execCmd.Stdout = &stdoutBuf
		execCmd.Stderr = &stderrBuf
		if err := execCmd.Run(); err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				if s, ok := e.Sys().(syscall.WaitStatus); ok {
					return s.ExitStatus(), stdoutBuf.String(), stderrBuf.String(), nil
				} else {
					return 998, stdoutBuf.String(), stderrBuf.String(), nil
				}
			} else {
				return 999, stdoutBuf.String(), stderrBuf.String(), nil
			}
		} else {
			return 0, stdoutBuf.String(), stderrBuf.String(), nil
		}
	case "ssh-config":
		sshBinPath, err := exec.LookPath("ssh")
		if err != nil {
			return 0, "", "", errors.Wrap(err, "look path to ssh")
		}
		args := []string{"-tt", "-F", *h.Config.SSHConfig, *h.Config.Host, fmt.Sprintf("stty cols 1000; %s", cmd)}

		execCmd := exec.CommandContext(ctx, sshBinPath, args...)
		var stdoutBuf, stderrBuf bytes.Buffer
		execCmd.Stdout = &stdoutBuf
		execCmd.Stderr = &stderrBuf
		if err := execCmd.Run(); err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				if s, ok := e.Sys().(syscall.WaitStatus); ok {
					return s.ExitStatus(), stdoutBuf.String(), stderrBuf.String(), nil
				} else {
					return 998, stdoutBuf.String(), stderrBuf.String(), nil
				}
			} else {
				return 999, stdoutBuf.String(), stderrBuf.String(), nil
			}
		} else {
			return 0, stdoutBuf.String(), stderrBuf.String(), nil
		}
	default:
		return 0, "", "", errors.Errorf("%s is not implemented", h.Config.Type)
	}
}

type Packages struct {
	Kernel Kernel
	OSPkg  map[string]Package
	CPE    map[string]common.WellFormedName
	// LangPkg LangPkg
	// Lockfile Lockfile
	// WordPress WordPress
	// KB KB
}

type Kernel struct {
	Version         string
	Release         string
	RebootRrequired bool
}

type Package struct {
	Name            string
	Version         string
	Release         string
	NewVersion      string
	NewRelease      string
	Arch            string
	Vendor          string
	Repository      string
	ModularityLabel string

	SrcName    string
	SrcVersion string
	SrcArch    string
}

type VulnInfo struct {
	ID               string
	Content          types.Vulnerability
	AffectedPackages []AffectedPackage
}

type AffectedPackage struct {
	Name       string
	Source     string
	Status     string
	AffectedIn string
	FixedIn    string
}

type Config struct {
	Type      string  `json:"type"`
	Host      *string `json:"host"`
	Port      *string `json:"port"`
	User      *string `json:"user"`
	SSHConfig *string `json:"ssh_config"`
	SSHKey    *string `json:"ssh_key"`
	Scan      *config.Scan
	Detect    *config.Detect
	Report    *config.Report
}
