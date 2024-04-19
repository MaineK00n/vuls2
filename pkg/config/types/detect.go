package types

type DetectConfig struct {
	VulnDB struct {
		Type string `json:"type"`
		Path string `json:"path"`
	} `json:"vulndb"`
	WordPress *struct {
		Token    string `json:"token"`
		Inactive bool   `json:"inactive"`
	} `json:"wordpress"`
}
