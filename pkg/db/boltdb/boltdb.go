package boltdb

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/exp/maps"

	"github.com/MaineK00n/vuls2/pkg/db/types"
)

type options struct {
}

type Option interface {
	apply(*options)
}

type DB struct {
	conn *bolt.DB
}

func Open(dbPath string, debug bool, opts ...Option) (*DB, error) {
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		return nil, errors.Wrap(err, "open boltdb")
	}
	return &DB{conn: db}, nil
}

func (db *DB) Close() error {
	if db.conn == nil {
		return nil
	}
	if err := db.conn.Close(); err != nil {
		return errors.Wrap(err, "close boltdb")
	}
	return nil
}

func (db *DB) PutVulnerability(src, key string, value types.Vulnerability) error {
	bucket, id, found := strings.Cut(key, ":")
	if !found {
		return errors.Errorf(`unexpected key. accepts: "vulnerability:<Vulnerability ID>, received: "%s"`, key)
	}
	if err := db.conn.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return errors.Wrapf(err, "create %s bucket", bucket)
		}

		vb, err := b.CreateBucketIfNotExists([]byte(id))
		if err != nil {
			return errors.Wrapf(err, "create %s/%s bucket", bucket, id)
		}

		bs, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return errors.Wrap(err, "marshal json")
		}

		if err := vb.Put([]byte(src), bs); err != nil {
			return errors.Wrapf(err, "put %%s/%s/%s", bucket, id, src)
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "update db")
	}

	return nil
}

func (db *DB) PutPackage(src, key string, value map[string]types.Packages) error {
	if err := db.conn.Update(func(tx *bolt.Tx) error {
		name, version, found := strings.Cut(key, ":")
		if !found && name == "" {
			return errors.Errorf(`unexpected key. accepts: "<osname>(:<version>)", received: "%s"`, key)
		}

		bucket := name
		b, err := tx.CreateBucketIfNotExists([]byte(name))
		if err != nil {
			return errors.Wrapf(err, "create %s bucket", name)
		}
		switch name {
		case "arch", "freebsd", "gentoo":
		case "redhat":
			if version == "" {
				return errors.Errorf(`unexpected key. accepts: "<osname>:<version>", received: "%s"`, key)
			}
			b, err = b.CreateBucketIfNotExists([]byte(version[:1]))
			if err != nil {
				return errors.Wrapf(err, "create %s/%s bucket", name, version[:1])
			}
			b, err = b.CreateBucketIfNotExists([]byte(version))
			if err != nil {
				return errors.Wrapf(err, "create %s/%s/%s bucket", name, version[:1], version)
			}
			bucket = fmt.Sprintf("%s/%s/%s", name, version[:1], version)
		default:
			if version == "" {
				return errors.Errorf(`unexpected key. accepts: "<osname>:<version>", received: "%s"`, key)
			}
			b, err = b.CreateBucketIfNotExists([]byte(version))
			if err != nil {
				return errors.Wrapf(err, "crate %s/%s bucket", name, version)
			}
			bucket = fmt.Sprintf("%s/%s", name, version)
		}

		for n, v := range value {
			pb, err := b.CreateBucketIfNotExists([]byte(n))
			if err != nil {
				return errors.Wrapf(err, "create %s/%s bucket", bucket, n)
			}

			vb, err := pb.CreateBucketIfNotExists([]byte(v.ID))
			if err != nil {
				return errors.Wrapf(err, "create %s/%s/%s bucket", bucket, n, v.ID)
			}

			var p map[string]types.Package
			bs := vb.Get([]byte(src))
			if len(bs) > 0 {
				if err := json.Unmarshal(bs, &p); err != nil {
					return errors.Wrap(err, "unmarshal json")
				}
			} else {
				p = map[string]types.Package{}
			}
			maps.Copy(p, v.Package)
			bs, err = json.MarshalIndent(p, "", "  ")
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := vb.Put([]byte(src), bs); err != nil {
				return errors.Wrapf(err, "put %s", key)
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "update db")
	}

	return nil
}

func (db *DB) PutCPEConfiguration(src, key string, value map[string]types.CPEConfigurations) error {
	if err := db.conn.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(key))
		if err != nil {
			return errors.Wrapf(err, "create %s bucket", key)
		}

		for pvp, c := range value {
			pvpb, err := b.CreateBucketIfNotExists([]byte(pvp))
			if err != nil {
				return errors.Wrapf(err, "create %s/%s bucket", key, pvp)
			}

			vb, err := pvpb.CreateBucketIfNotExists([]byte(c.ID))
			if err != nil {
				return errors.Wrapf(err, "create %s/%s/%s bucket", key, pvp, c.ID)
			}

			var v map[string][]types.CPEConfiguration
			bs := vb.Get([]byte(src))
			if len(bs) > 0 {
				if err := json.Unmarshal(bs, &v); err != nil {
					return errors.Wrap(err, "unmarshal json")
				}
			} else {
				v = map[string][]types.CPEConfiguration{}
			}
			maps.Copy(v, c.Configuration)
			bs, err = json.MarshalIndent(v, "", "  ")
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := vb.Put([]byte(src), bs); err != nil {
				return errors.Wrapf(err, "put %s", key)
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "update db")
	}

	return nil
}

func (db *DB) PutRedHatRepoToCPE(src, key string, value types.RepositoryToCPE) error {
	if err := db.conn.Update(func(tx *bolt.Tx) error {
		name, version, found := strings.Cut(key, ":")
		if !found && name == "" {
			return errors.Errorf(`unexpected key. accepts: "redhat_cpe:<version>", received: "%s"`, key)
		}

		b, err := tx.CreateBucketIfNotExists([]byte(name))
		if err != nil {
			return errors.Wrapf(err, "create %s bucket", name)
		}

		b, err = b.CreateBucketIfNotExists([]byte(version[:1]))
		if err != nil {
			return errors.Wrapf(err, "create %s/%s bucket", name, version[:1])
		}

		b, err = b.CreateBucketIfNotExists([]byte(version))
		if err != nil {
			return errors.Wrapf(err, "create %s/%s/%s bucket", name, version[:1], version)
		}

		for repo, cpes := range value {
			rb, err := b.CreateBucketIfNotExists([]byte(repo))
			if err != nil {
				return errors.Wrapf(err, "create %s/%s/%s/%s bucket", name, version[:1], version, repo)
			}

			bs, err := json.MarshalIndent(cpes, "", "  ")
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := rb.Put([]byte(src), bs); err != nil {
				return errors.Wrapf(err, "put %s", key)
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "update db")
	}

	return nil
}

func (db *DB) GetVulnerability(ids []string) (map[string]map[string]types.Vulnerability, error) {
	r := map[string]map[string]types.Vulnerability{}
	if err := db.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("vulnerability"))
		if b == nil {
			return nil
		}
		for _, id := range ids {
			vb := b.Bucket([]byte(id))
			if vb == nil {
				return nil
			}
			r[string(id)] = map[string]types.Vulnerability{}
			if err := vb.ForEach(func(src, bs []byte) error {
				var v types.Vulnerability
				if err := json.Unmarshal(bs, &v); err != nil {
					return errors.Wrapf(err, "decode %s/%s", string(id), string(src))
				}
				r[string(id)][string(src)] = v

				return nil
			}); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return r, nil
}

func (db *DB) GetPackage(family, release string, name string) (map[string]map[string]map[string]types.Package, error) {
	r := map[string]map[string]map[string]types.Package{}
	if err := db.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(family))
		if b == nil {
			return nil
		}
		switch family {
		case "debian", "ubuntu":
			b = b.Bucket([]byte(release))
			if b == nil {
				return nil
			}
			b = b.Bucket([]byte(name))
			if b == nil {
				return nil
			}

			if err := b.ForEach(func(cveid, _ []byte) error {
				vb := b.Bucket(cveid)
				r[string(cveid)] = map[string]map[string]types.Package{}
				if err := vb.ForEach(func(src, bs []byte) error {
					var v map[string]types.Package
					if err := json.Unmarshal(bs, &v); err != nil {
						return errors.Wrapf(err, "decode %s/%s", string(cveid), string(src))
					}
					r[string(cveid)][string(src)] = v

					return nil
				}); err != nil {
					return err
				}
				return nil
			}); err != nil {
				return err
			}
		default:
			return errors.New("not implemented")
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return r, nil
}

func (db *DB) GetCPEConfiguration(cpes []string) (map[string]map[string][]types.CPEConfiguration, error) {
	return nil, nil
}
