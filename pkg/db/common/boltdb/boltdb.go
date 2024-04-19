package boltdb

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/common/util"
	"github.com/MaineK00n/vuls2/pkg/types"
)

type Config struct {
	Path string
}

type Connection struct {
	Config *Config

	conn *bolt.DB
}

func (c *Connection) Open() error {
	if c.Config == nil {
		return errors.New("connection config is not set")
	}

	db, err := bolt.Open(c.Config.Path, 0600, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	c.conn = db
	return nil
}

func (c *Connection) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Connection) GetMetadata() (*types.Metadata, error) {
	var v types.Metadata
	if err := c.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("metadata"))
		if b == nil {
			return errors.Errorf("bucket:%q is not exists", "metadata")
		}

		if err := util.Unmarshal(b.Get([]byte("db")), false, &v); err != nil {
			return errors.Wrap(err, "unmarshal metadata:db")
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return &v, nil
}

func (c *Connection) PutMetadata(metadata types.Metadata) error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("metadata"))
		if err != nil {
			return errors.Wrapf(err, "create bucket:%q if not exists", "metadata")
		}

		bs, err := util.Marshal(metadata, false)
		if err != nil {
			return errors.Wrap(err, "marshal metadata")
		}

		if err := b.Put([]byte("db"), bs); err != nil {
			return errors.Wrap(err, "put metadata:db")
		}

		return nil
	})
}

func (c *Connection) GetVulnerabilityDetections(ecosystem, key string) (<-chan struct {
	ID        string
	Detection detectionTypes.Detection
}, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetVulnerabilityDatas() (<-chan types.VulnerabilityData, error) {
	return nil, errors.New("not implemented yet")
}

func (c *Connection) GetVulnerabilityData(id string) (*types.VulnerabilityData, error) {
	var data types.VulnerabilityData
	if err := c.conn.View(func(tx *bolt.Tx) error {
		vb := tx.Bucket([]byte("vulnerability"))
		if vb == nil {
			return errors.Errorf("bucket:%q is not exists", "vulnerability")
		}

		vrb := vb.Bucket([]byte("root"))
		if vrb == nil {
			return errors.Errorf("bucket:%q is not exists", "vulnerability:root")
		}

		bs := vrb.Get([]byte(id))
		if len(bs) == 0 {
			return nil
		}

		var root types.VulnerabilityRoot
		if err := util.Unmarshal(bs, true, &root); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability:root:%s", id))
		}
		data.ID = root.ID

		am := map[string]types.VulnerabilityDataAdvisory{}
		for _, qs := range root.Advisories {
			if len(qs) != 3 {
				return errors.Errorf("unexpected advisory queries. expected: %q, actual: %q", []string{"<Advisory ID>", "<Source ID>", "<Root ID>"}, qs)
			}

			vab := vb.Bucket([]byte("advisory"))
			if vab == nil {
				return errors.Errorf("bucket:%q is not exists", "vulnerability:advisory")
			}

			vaab := vab.Bucket([]byte(qs[0]))
			if vaab == nil {
				return errors.Errorf("bucket:%q is not exists", fmt.Sprintf("vulnerability:advisory:%s", qs[0]))
			}

			vaasb := vaab.Bucket([]byte(qs[1]))
			if vaasb == nil {
				return errors.Errorf("bucket:%q is not exists", fmt.Sprintf("vulnerability:advisory:%s:%s", qs[0], qs[1]))
			}

			var a types.VulnerabilityAdvisory
			if err := util.Unmarshal(vaasb.Get([]byte(qs[2])), true, &a); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability:advisory:%s:%s:%s", qs[0], qs[1], qs[2]))
			}

			da, ok := am[a.Content.ID]
			if !ok {
				da = types.VulnerabilityDataAdvisory{
					ID:       a.Content.ID,
					Contents: map[sourceTypes.SourceID]map[string][]types.VulnerabilityAdvisory{},
				}
			}
			dac, ok := da.Contents[sourceTypes.SourceID(qs[1])]
			if !ok {
				dac = map[string][]types.VulnerabilityAdvisory{}
			}
			dac[qs[2]] = append(dac[qs[2]], a)
			da.Contents[sourceTypes.SourceID(qs[1])] = dac
			am[a.Content.ID] = da
		}
		for _, a := range am {
			data.Advisories = append(data.Advisories, a)
		}

		vm := map[string]types.VulnerabilityDataVulnerability{}
		for _, qs := range root.Vulnerabilities {
			if len(qs) != 3 {
				return errors.Errorf("unexpected vulnerability queries. expected: %q, actual: %q", []string{"<CVE ID>", "<Source ID>", "<Root ID>"}, qs)
			}

			vvb := vb.Bucket([]byte("vulnerability"))
			if vvb == nil {
				return errors.Errorf("bucket:%q is not exists", "vulnerability:vulnerability")
			}

			vvvb := vvb.Bucket([]byte(qs[0]))
			if vvvb == nil {
				return errors.Errorf("bucket:%q is not exists", fmt.Sprintf("vulnerability:vulnerability:%s", qs[0]))
			}

			vvvsb := vvvb.Bucket([]byte(qs[1]))
			if vvvsb == nil {
				return errors.Errorf("bucket:%q is not exists", fmt.Sprintf("vulnerability:vulnerability:%s:%s", qs[0], qs[1]))
			}

			var v types.VulnerabilityVulnerability
			if err := util.Unmarshal(vvvsb.Get([]byte(qs[2])), true, &v); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability:vulnerability:%s:%s:%s", qs[0], qs[1], qs[2]))
			}

			dv, ok := vm[v.Content.ID]
			if !ok {
				dv = types.VulnerabilityDataVulnerability{
					ID:       v.Content.ID,
					Contents: map[sourceTypes.SourceID]map[string][]types.VulnerabilityVulnerability{},
				}
			}
			dvc, ok := dv.Contents[sourceTypes.SourceID(qs[1])]
			if !ok {
				dvc = map[string][]types.VulnerabilityVulnerability{}
			}
			dvc[qs[2]] = append(dvc[qs[2]], v)
			dv.Contents[sourceTypes.SourceID(qs[1])] = dvc
			vm[v.Content.ID] = dv
		}
		for _, v := range vm {
			data.Vulnerabilities = append(data.Vulnerabilities, v)
		}

		dm := map[detectionTypes.Ecosystem]types.VulnerabilityDataDetection{}
		for _, qs := range root.Detections {
			if len(qs) != 4 {
				return errors.Errorf("unexpected detection queries. expected: %q, actual: %q", []string{"<Ecosystem>", "<Package name | CPE>", "<Root ID>", "<Source ID>"}, qs)
			}

			eb := tx.Bucket([]byte(qs[0]))
			if eb == nil {
				return errors.Errorf("bucket:%q is not exists", qs[0])
			}

			epb := eb.Bucket([]byte(qs[1]))
			if epb == nil {
				return errors.Errorf("bucket:%q is not exists", fmt.Sprintf("%s:%s", qs[0], qs[1]))
			}

			eprb := epb.Bucket([]byte(qs[2]))
			if eprb == nil {
				return errors.Errorf("bucket:%q is not exists", fmt.Sprintf("%s:%s:%s", qs[0], qs[1], qs[2]))
			}

			var d []detectionTypes.Detection
			if err := util.Unmarshal(eprb.Get([]byte(qs[3])), false, &d); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s:%s:%s:%s", qs[0], qs[1], qs[2], qs[3]))
			}

			dd, ok := dm[detectionTypes.Ecosystem(qs[0])]
			if !ok {
				dd = types.VulnerabilityDataDetection{
					Ecosystem: detectionTypes.Ecosystem(qs[0]),
					Contents:  map[sourceTypes.SourceID][]detectionTypes.Detection{},
				}
			}
			dd.Contents[sourceTypes.SourceID(qs[3])] = append(dd.Contents[sourceTypes.SourceID(qs[3])], d...)
			dm[detectionTypes.Ecosystem(qs[0])] = dd
		}
		for _, d := range dm {
			data.Detections = append(data.Detections, d)
		}

		for _, q := range root.DataSources {
			sb := tx.Bucket([]byte("datasource"))
			if sb == nil {
				return errors.Errorf("bucket:%q is not exists", "datasource")
			}

			var d datasourceTypes.DataSource
			if err := util.Unmarshal(sb.Get([]byte(q)), false, &d); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("datasource:%s", q))
			}

			data.DataSources = append(data.DataSources, d)
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return &data, nil
}

func (c *Connection) PutVulnerabilityData(root string) error {
	tx, err := c.conn.Begin(true)
	if err != nil {
		return errors.Wrap(err, "start a new transaction")
	}

	roots := map[string]types.VulnerabilityRoot{}
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var data dataTypes.Data
		if err := json.NewDecoder(f).Decode(&data); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		ecosystems := func() []detectionTypes.Ecosystem {
			var es []detectionTypes.Ecosystem
			for _, d := range data.Detection {
				es = append(es, d.Ecosystem)
			}
			return es
		}()

		vb, err := tx.CreateBucketIfNotExists([]byte("vulnerability"))
		if err != nil {
			return errors.Wrapf(err, "create bucket:%q if not exists", "vulnerability")
		}

		vab, err := vb.CreateBucketIfNotExists([]byte("advisory"))
		if err != nil {
			return errors.Wrapf(err, "create bucket:%q if not exists", "vulnerability:advisory")
		}
		for _, a := range data.Advisories {
			vaab, err := vab.CreateBucketIfNotExists([]byte(a.ID))
			if err != nil {
				return errors.Wrapf(err, "create bucket:%q if not exists", fmt.Sprintf("vulnerability:advisory:%s", a.ID))
			}

			vaasb, err := vaab.CreateBucketIfNotExists([]byte(data.DataSource))
			if err != nil {
				return errors.Wrapf(err, "create bucket:%q if not exists", fmt.Sprintf("vulnerability:advisory:%s:%s", a.ID, data.DataSource))
			}

			bs, err := util.Marshal(types.VulnerabilityAdvisory{
				Content:    a,
				Ecosystems: ecosystems,
			}, true)
			if err != nil {
				return errors.Wrap(err, "marshal advisory")
			}

			if err := vaasb.Put([]byte(data.ID), bs); err != nil {
				return errors.Wrapf(err, "put %s", fmt.Sprintf("vulnerability:advisory:%s:%s:%s", a.ID, data.DataSource, data.ID))
			}

			r, ok := roots[data.ID]
			if !ok {
				r = types.VulnerabilityRoot{ID: data.ID}
			}
			r.Advisories = append(r.Advisories, []string{a.ID, string(data.DataSource), data.ID})
			roots[data.ID] = r
		}

		vvb, err := vb.CreateBucketIfNotExists([]byte("vulnerability"))
		if err != nil {
			return errors.Wrapf(err, "create bucket:%q if not exists", "vulnerability:vulnerability")
		}
		for _, v := range data.Vulnerabilities {
			vvvb, err := vvb.CreateBucketIfNotExists([]byte(v.ID))
			if err != nil {
				return errors.Wrapf(err, "create bucket:%q if not exists", fmt.Sprintf("vulnerability:vulnerability:%s", v.ID))
			}

			vvvsb, err := vvvb.CreateBucketIfNotExists([]byte(data.DataSource))
			if err != nil {
				return errors.Wrapf(err, "create bucket:%q if not exists", fmt.Sprintf("vulnerability:vulnerability:%s:%s", v.ID, data.DataSource))
			}

			bs, err := util.Marshal(types.VulnerabilityVulnerability{
				Content:    v,
				Ecosystems: ecosystems,
			}, true)
			if err != nil {
				return errors.Wrap(err, "marshal vulnerability")
			}

			if err := vvvsb.Put([]byte(data.ID), bs); err != nil {
				return errors.Wrapf(err, "put %s", fmt.Sprintf("vulnerability:vulnerability:%s:%s:%s", v.ID, data.DataSource, data.ID))
			}

			r, ok := roots[data.ID]
			if !ok {
				r = types.VulnerabilityRoot{ID: data.ID}
			}
			r.Vulnerabilities = append(r.Vulnerabilities, []string{v.ID, string(data.DataSource), data.ID})
			roots[data.ID] = r

			if v.ID != data.ID {
				r, ok := roots[v.ID]
				if !ok {
					r = types.VulnerabilityRoot{ID: v.ID}
				}
				r.Vulnerabilities = append(r.Vulnerabilities, []string{v.ID, string(data.DataSource), data.ID})
				roots[v.ID] = r
			}
		}

		// for _, d := range data.Detection {
		// 	eb, err := tx.CreateBucketIfNotExists([]byte(d.Ecosystem))
		// 	if err != nil {
		// 		return errors.Wrapf(err, "create bucket:%q if not exists", d.Ecosystem)
		// 	}
		// 	d.Criteria
		// }

		r, ok := roots[data.ID]
		if !ok {
			r = types.VulnerabilityRoot{ID: data.ID}
		}
		r.DataSources = append(r.DataSources, string(data.DataSource))
		roots[data.ID] = r

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", root)
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "commit transaction")
	}

	tx, err = c.conn.Begin(true)
	if err != nil {
		return errors.Wrap(err, "start a new transaction")
	}

	for _, r := range roots {
		vb := tx.Bucket([]byte("vulnerability"))
		if vb == nil {
			return errors.Errorf("bucket:%q is not exists", "vulnerability")
		}

		vrb, err := vb.CreateBucketIfNotExists([]byte("root"))
		if err != nil {
			return errors.Wrapf(err, "create bucket:%q if not exists", "vulnerability:root")
		}

		bs := vrb.Get([]byte(r.ID))
		if len(bs) > 0 {
			var v types.VulnerabilityRoot
			if err := util.Unmarshal(bs, true, &v); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability:root:%s", r.ID))
			}
			for _, as := range v.Advisories {
				if !slices.ContainsFunc(r.Advisories, func(e []string) bool {
					return slices.Equal(e, as)
				}) {
					r.Advisories = append(r.Advisories, as)
				}
			}
			for _, vs := range v.Vulnerabilities {
				if !slices.ContainsFunc(r.Vulnerabilities, func(e []string) bool {
					return slices.Equal(e, vs)
				}) {
					r.Vulnerabilities = append(r.Vulnerabilities, vs)
				}
			}
			for _, ds := range v.Detections {
				if !slices.ContainsFunc(r.Detections, func(e []string) bool {
					return slices.Equal(e, ds)
				}) {
					r.Detections = append(r.Detections, ds)
				}
			}
			for _, d := range v.DataSources {
				if !slices.Contains(r.DataSources, d) {
					r.DataSources = append(r.DataSources, d)
				}
			}
		}

		bs, err = util.Marshal(r, true)
		if err != nil {
			return errors.Wrap(err, "marshal root")
		}

		if err := vrb.Put([]byte(r.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("vulnerability:root:%s", r.ID))
		}
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "commit transaction")
	}

	return nil
}

func (c *Connection) GetDataSource(id sourceTypes.SourceID) (*datasourceTypes.DataSource, error) {
	var v datasourceTypes.DataSource
	if err := c.conn.View(func(tx *bolt.Tx) error {
		sb := tx.Bucket([]byte("datasource"))
		if sb == nil {
			return errors.Errorf("bucket:%q is not exists", "datasource")
		}

		if err := util.Unmarshal(sb.Get([]byte(id)), false, &v); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("datasource:%s", id))
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return &v, nil
}

func (c *Connection) PutDataSource(root string) error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		sb, err := tx.CreateBucketIfNotExists([]byte("datasource"))
		if err != nil {
			return errors.Wrapf(err, "create bucket:%q if not exists", "datasource")
		}

		f, err := os.Open(root)
		if err != nil {
			return errors.Wrapf(err, "open %s", root)
		}
		defer f.Close()

		var datasource datasourceTypes.DataSource
		if err := json.NewDecoder(f).Decode(&datasource); err != nil {
			return errors.Wrapf(err, "decode %s", root)
		}

		bs, err := util.Marshal(datasource, false)
		if err != nil {
			return errors.Wrap(err, "marshal datasource")
		}

		if err := sb.Put([]byte(datasource.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("datasource:%s", datasource.ID))
		}

		return nil
	})
}
