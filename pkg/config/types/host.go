package types

type HostConfig struct {
	Name   string
	Scan   *ScanConfig
	Detect *DetectConfig
	Report *ReportConfig
	Server *ServerConfig
}

type HostScanConfig struct {
	Inside *struct {
		Type  string `json:"type"` // local, remote, pseudo, file
		Local *struct {
			RootPrivilege bool `json:"root_privilege"`
			Offline       bool `json:"offline"`
			ScanModlue    struct {
				Package *struct {
					Windows *struct {
						ServerSelection int    `json:"server_selection"`
						CabPath         string `json:"cab_path"`
					} `json:"windows"`
				} `json:"package"`
				CPE     []string `json:"cpe"`
				Library *struct {
					FindLibrary      bool     `json:"find_library"`
					FindLibraryRoots []string `json:"find_library_roots"`
					LibraryFiles     []string `json:"library_files"`
				} `json:"library"`
				Port *struct {
					Type   string    `json:"type"` // native, nmap
					Native *struct{} `json:"native"`
					Nmap   *struct {
						RootPrivilege  bool     `json:"root_privilege"`
						ScanTechniques []string `json:"scan_techniques"`
						SourcePort     int      `json:"source_port"`
					} `json:"nmap"`
				} `json:"port"`
				GitHub []struct {
					Repository            string `json:"repository"`
					Token                 string `json:"token"`
					IgnoreGitHubDismissed bool   `json:"ignore_github_dismissed"`
				} `json:"github"`
				WordPress *struct {
					WPScanPath    string `json:"wp_scan_path"`
					DocumentOwner string `json:"document_owner"`
					DocumentRoot  string `json:"document_root"`
				} `json:"wordpress"`
			} `json:"scan_modlue"`
			VM        []struct{} `json:"vm"`
			Container []struct {
				Type       string `json:"type"` // docker, lxd, lxc
				Name       string `json:"name"`
				ScanModule struct {
					Package *struct {
						Windows *struct {
							ServerSelection int    `json:"server_selection"`
							CabPath         string `json:"cab_path"`
						} `json:"windows"`
					} `json:"package"`
					CPE     []string `json:"cpe"`
					Library *struct {
						FindLibrary      bool     `json:"find_library"`
						FindLibraryRoots []string `json:"find_library_roots"`
						LibraryFiles     []string `json:"library_files"`
					} `json:"library"`
					Port *struct {
						Type   string    `json:"type"` // native, nmap
						Native *struct{} `json:"native"`
						Nmap   *struct {
							RootPrivilege  bool     `json:"root_privilege"`
							ScanTechniques []string `json:"scan_techniques"`
							SourcePort     int      `json:"source_port"`
						} `json:"nmap"`
					} `json:"port"`
					GitHub []struct {
						Repository            string `json:"repository"`
						Token                 string `json:"token"`
						IgnoreGitHubDismissed bool   `json:"ignore_github_dismissed"`
					} `json:"github"`
					WordPress *struct {
						WPScanPath    string `json:"wp_scan_path"`
						DocumentOwner string `json:"document_owner"`
						DocumentRoot  string `json:"document_root"`
					} `json:"wordpress"`
				} `json:"scan_module"`
			} `json:"container"`
		} `json:"local"`
		Remote *struct {
			Host          string `json:"host"`
			Port          int    `json:"port"`
			User          string `json:"user"`
			SSHKey        string `json:"ssh_key"`
			SSHConfig     string `json:"ssh_config"`
			RootPrivilege bool   `json:"root_privilege"`
			Offline       bool   `json:"offline"`
			ScanModlue    struct {
				Package *struct {
					Windows *struct {
						ServerSelection int    `json:"server_selection"`
						CabPath         string `json:"cab_path"`
					} `json:"windows"`
				} `json:"package"`
				CPE     []string `json:"cpe"`
				Library *struct {
					FindLibrary      bool     `json:"find_library"`
					FindLibraryRoots []string `json:"find_library_roots"`
					LibraryFiles     []string `json:"library_files"`
				} `json:"library"`
				Port *struct {
					Type   string    `json:"type"` // native, nmap
					Native *struct{} `json:"native"`
					Nmap   *struct {
						RootPrivilege  bool     `json:"root_privilege"`
						ScanTechniques []string `json:"scan_techniques"`
						SourcePort     int      `json:"source_port"`
					} `json:"nmap"`
				} `json:"port"`
				GitHub []struct {
					Repository            string `json:"repository"`
					Token                 string `json:"token"`
					IgnoreGitHubDismissed bool   `json:"ignore_github_dismissed"`
				} `json:"github"`
				WordPress *struct {
					WPScanPath    string `json:"wp_scan_path"`
					DocumentOwner string `json:"document_owner"`
					DocumentRoot  string `json:"document_root"`
				} `json:"wordpress"`
			} `json:"scan_modlue"`
			VM        []struct{} `json:"vm"`
			Container []struct {
				Type       string `json:"type"` // docker, lxd, lxc
				Name       string `json:"name"`
				ScanModule struct {
					Package *struct {
						Windows *struct {
							ServerSelection int    `json:"server_selection"`
							CabPath         string `json:"cab_path"`
						} `json:"windows"`
					} `json:"package"`
					CPE     []string `json:"cpe"`
					Library *struct {
						FindLibrary      bool     `json:"find_library"`
						FindLibraryRoots []string `json:"find_library_roots"`
						LibraryFiles     []string `json:"library_files"`
					} `json:"library"`
					Port *struct {
						Type   string    `json:"type"` // native, nmap
						Native *struct{} `json:"native"`
						Nmap   *struct {
							RootPrivilege  bool     `json:"root_privilege"`
							ScanTechniques []string `json:"scan_techniques"`
							SourcePort     int      `json:"source_port"`
						} `json:"nmap"`
					} `json:"port"`
					GitHub []struct {
						Repository            string `json:"repository"`
						Token                 string `json:"token"`
						IgnoreGitHubDismissed bool   `json:"ignore_github_dismissed"`
					} `json:"github"`
					WordPress *struct {
						WPScanPath    string `json:"wp_scan_path"`
						DocumentOwner string `json:"document_owner"`
						DocumentRoot  string `json:"document_root"`
					} `json:"wordpress"`
				} `json:"scan_module"`
			} `json:"container"`
		} `json:"remote"`
		Pseudo *struct {
			ScanModlue struct {
				CPE     []string `json:"cpe"`
				Library *struct {
					LibraryFiles []string `json:"library_files"`
				} `json:"library"`
				GitHub []struct {
					Repository            string `json:"repository"`
					Token                 string `json:"token"`
					IgnoreGitHubDismissed bool   `json:"ignore_github_dismissed"`
				} `json:"github"`
			} `json:"scan_modlue"`
		} `json:"pseudo"`
		File *struct {
			Type string `json:"type"`
			Path string `json:"path"`
		} `json:"file"`
	} `json:"inside"`
	ASM           *struct{} `json:"asm"`
	Configuration *struct{} `json:"configuration"`
}

type HostDetectConfig struct {
	Ignore struct {
		Unfixed   bool     `json:"unfixed"`
		UnScored  bool     `json:"unscored"`
		CVE       []string `json:"cve"`
		Package   []string `json:"package"`
		CVSSUnder float64  `json:"cvss_under"`
	} `json:"ignore"`
}

type HostReportConfig struct {
	Stdout        bool
	CSV           bool `json:"csv"`
	XML           bool `json:"xml"`
	CycloneDXJSON bool
	CycloneDXXML  bool
	SPDXJSON      bool
	SPDXXML       bool
	HTTP          []string
	EMail         []string
	Syslog        []string
	Slack         []string
	ChatWork      []string
	Telegram      []string
	S3            []string
	GCS           []string
	AzureBlob     []string
}

type HostServerConfig struct {
	Ignore struct {
		Unfixed   bool     `json:"unfixed"`
		UnScored  bool     `json:"unscored"`
		CVE       []string `json:"cve"`
		Package   []string `json:"package"`
		CVSSUnder float64  `json:"cvss_under"`
	} `json:"ignore"`
}
