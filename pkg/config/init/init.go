package init

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/config/detect"
	"github.com/MaineK00n/vuls2/pkg/config/types"
	"github.com/MaineK00n/vuls2/pkg/config/util"
)

type options struct {
	config string
}

type Option interface {
	apply(*options)
}

type configOption string

func (o configOption) apply(opts *options) {
	opts.config = string(o)
}

func WithConfig(config string) Option {
	return configOption(config)
}

func Init(opts ...Option) error {
	options := &options{
		config: func() string {
			d, err := os.UserConfigDir()
			if err != nil {
				return "config.json"
			}
			return filepath.Join(d, "vuls", "config.json")
		}(),
	}
	for _, o := range opts {
		o.apply(options)
	}

	fmt.Println("initialize config")

	c := types.Config{
		Detect: &types.DetectConfig{},
	}
	detect.Fill(c.Detect)
	fmt.Println(c.Detect)

	if err := util.Write(options.config, c); err != nil {
		return errors.Wrap(err, "write config")
	}

	fmt.Printf("initialized success. config: %s\n", options.config)

	return nil
}
