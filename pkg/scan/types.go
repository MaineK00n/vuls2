package scan

type scanResult struct {
	ServerName string `json:"serverName"` // TOML Section key
	Family     string `json:"family"`
	Release    string `json:"release"`

	RunningKernel kernel                `json:"runningKernel"`
	Packages      map[string]binPackage `json:"packages"`
	SrcPackages   map[string]srcPackage `json:",omitempty"`

	Config struct {
		Scan config `json:"scan"`
	}
}

type kernel struct {
	Release        string `json:"release"`
	Version        string `json:"version"`
	RebootRequired bool   `json:"rebootRequired"`
}

type binPackage struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Release         string `json:"release"`
	NewVersion      string `json:"newVersion"`
	NewRelease      string `json:"newRelease"`
	Arch            string `json:"arch"`
	Repository      string `json:"repository"`
	ModularityLabel string `json:"modularitylabel"`
	// Changelog        *Changelog           `json:"changelog,omitempty"`
	// AffectedProcs    []AffectedProcess    `json:",omitempty"`
	// NeedRestartProcs []NeedRestartProcess `json:",omitempty"`
}

type srcPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Arch        string   `json:"arch"`
	BinaryNames []string `json:"binaryNames"`
}

type config struct {
	Servers map[string]struct {
		CpeNames []string `json:"cpeNames,omitempty"`
	} `json:"servers,omitempty"`
}
