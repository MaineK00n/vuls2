package util

import (
	"encoding/json"
	"os"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/config/types"
)

func Load(path string) (*types.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	var c types.Config
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return nil, errors.Wrapf(err, "decode %s", path)
	}

	return &c, nil
}

func Write(path string, config types.Config) error {
	f, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "create %s", path)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(config); err != nil {
		return errors.Wrapf(err, "encode %s", path)
	}

	return nil
}
