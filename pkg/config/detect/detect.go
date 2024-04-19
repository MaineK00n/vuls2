package detect

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/config/types"
	"github.com/MaineK00n/vuls2/pkg/config/util"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
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

// bubletea
// example: simple, result, text input, multiple text inputs, credit card form,static progress, package manager, simple list, exec
// lipgloss

func Edit(opts ...Option) error {
	options := &options{
		config: filepath.Join(utilos.UserConfigDir(), "config.json"),
	}
	for _, o := range opts {
		o.apply(options)
	}

	fmt.Println("edit detect config")

	c, err := util.Load(options.config)
	if err != nil {
		return errors.Wrap(err, "load config")
	}

	Fill(c.Detect)

	fmt.Println(c.Detect)

	return nil
}

func Fill(base *types.DetectConfig) {
	fmt.Println("setting detect config")

	scanner := bufio.NewScanner(os.Stdin)
	if base == nil {
		base = &types.DetectConfig{}
	}

	for {
		fmt.Printf("vulndb type(default: %q): ", "boltdb")
		if base.VulnDB.Type != "" {
			fmt.Printf("%s", base.VulnDB.Type)
		}
		scanner.Scan()
		switch t := scanner.Text(); t {
		case "":
			base.VulnDB.Type = "boltdb"
		case "boltdb", "sqlite3", "mysql", "postgres", "redis":
			base.VulnDB.Type = t
		default:
			fmt.Printf("invalid vulndb type. accepts: %q\n", []string{"bolddb", "sqlite3", "mysql", "postgres", "redis"})
			continue
		}
		break
	}

	// fmt.Printf("vulndb path(default:%s): ", func() string {
	// 	switch c.Detect.VulnDB.Type {
	// 	case "boltdb":
	// 		return filepath.Join(utilos.UserCacheDir(), "vuls.db")
	// 	case "sqlite3":
	// 		return filepath.Join(utilos.UserCacheDir(), "vuls.sqlite3")
	// 	case "mysql":
	// 		return "vuls:vuls@tcp(127.0.0.1:3306)/vuls?parseTime=true"
	// 	case "postgres":
	// 		return "host=127.0.0.1 user=vuls dbname=vuls sslmode=disable password=vuls"
	// 	case "redis":
	// 		return "redis://127.0.0.1/0"
	// 	default:
	// 		return ""
	// 	}
	// }())
	// scanner.Scan()
	// switch t := scanner.Text(); t {
	// case "":
	// 	c.Detect.VulnDB.Path = func() string {
	// 		switch c.Detect.VulnDB.Type {
	// 		case "boltdb":
	// 			d, err := os.UserCacheDir()
	// 			if err != nil {
	// 				return "vuls.db"
	// 			}
	// 			return filepath.Join(d, "vuls", "vuls.db")
	// 		case "sqlite3":
	// 			d, err := os.UserCacheDir()
	// 			if err != nil {
	// 				return "vuls.sqlite3"
	// 			}
	// 			return filepath.Join(d, "vuls", "vuls.sqlite3")
	// 		case "mysql":
	// 			return "vuls:vuls@tcp(127.0.0.1:3306)/vuls?parseTime=true"
	// 		case "postgres":
	// 			return "host=127.0.0.1 user=vuls dbname=vuls sslmode=disable password=vuls"
	// 		case "redis":
	// 			return "redis://127.0.0.1/0"
	// 		default:
	// 			d, err := os.UserCacheDir()
	// 			if err != nil {
	// 				return "vuls.db"
	// 			}
	// 			return filepath.Join(d, "vuls", "vuls.db")
	// 		}
	// 	}()
	// default:
	// 	c.Detect.VulnDB.Path = t
	// }

	// c.Detect.WordPress = nil
}
