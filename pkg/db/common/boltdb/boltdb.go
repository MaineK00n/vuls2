package boltdb

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
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

func (c *Connection) GetMetadata() (*dbTypes.Metadata, error) {
	var v dbTypes.Metadata
	if err := c.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("metadata"))
		if b == nil {
			return errors.Errorf("bucket:%q is not exists", "metadata")
		}

		if err := util.Unmarshal(b.Get([]byte("db")), &v); err != nil {
			return errors.Wrap(err, "unmarshal metadata:db")
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return &v, nil
}

func (c *Connection) PutMetadata(metadata dbTypes.Metadata) error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("metadata"))
		if err != nil {
			return errors.Wrapf(err, "create bucket:%q if not exists", "metadata")
		}

		bs, err := util.Marshal(metadata)
		if err != nil {
			return errors.Wrap(err, "marshal metadata")
		}

		if err := b.Put([]byte("db"), bs); err != nil {
			return errors.Wrap(err, "put metadata:db")
		}

		return nil
	})
}

func (c *Connection) GetVulnerabilityDetections(ecosystem, key string) (<-chan types.VulnerabilityDataDetection, <-chan error) {
	resCh := make(chan types.VulnerabilityDataDetection, 1)
	errCh := make(chan error, 1)

	go func() {
		defer close(resCh)
		defer close(errCh)

		if err := c.conn.View(func(tx *bolt.Tx) error {
			eb := tx.Bucket([]byte(ecosystem))
			if eb == nil {
				return nil
			}

			epb := eb.Bucket([]byte(key))
			if epb == nil {
				return nil
			}

			if err := epb.ForEachBucket(func(rk []byte) error {
				eprb := epb.Bucket(rk)
				if eprb == nil {
					return errors.Errorf("bucket:%q is not exists", fmt.Sprintf("%s:%s:%s", ecosystem, key, rk))
				}

				m := map[sourceTypes.SourceID]map[string]criteriaTypes.Criteria{}
				var qs [][]string
				if err := eprb.ForEach(func(sk, v []byte) error {
					var k []string
					if err := util.Unmarshal(v, &k); err != nil {
						return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s:%s:%s:%s", ecosystem, key, rk, sk))
					}

					qs = append(qs, k)
					return nil
				}); err != nil {
					return errors.Wrapf(err, "walk %s", fmt.Sprintf("%s:%s:%s", ecosystem, key, rk))
				}

				db := tx.Bucket([]byte("detection"))
				if db == nil {
					return errors.Errorf("bucket:%q is not exists", "detection")
				}
				for _, q := range qs {
					if len(q) != 3 {
						return errors.Errorf("unexpected queries. expected: %q, actual: %q", []string{"<Root ID>", "<Source ID>", "<Ecosystem>"}, q)
					}

					drb := db.Bucket([]byte(q[0]))
					if drb == nil {
						return errors.Errorf("bucket:%q is not exists", fmt.Sprintf("%s:%s", "detection", q[0]))
					}

					drsb := drb.Bucket([]byte(q[1]))
					if drsb == nil {
						return errors.Errorf("bucket:%q is not exists", fmt.Sprintf("%s:%s:%s", "detection", q[0], q[1]))
					}

					var ca criteriaTypes.Criteria
					if err := util.Unmarshal(drsb.Get([]byte(q[2])), &ca); err != nil {
						return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s:%s:%s:%s", "detection", q[0], q[1], q[2]))
					}
					m[sourceTypes.SourceID(q[1])] = map[string]criteriaTypes.Criteria{q[0]: ca}
				}

				resCh <- types.VulnerabilityDataDetection{
					Ecosystem: detectionTypes.Ecosystem(ecosystem),
					Contents:  m,
				}

				return nil
			}); err != nil {
				return errors.Wrapf(err, "walk %s", fmt.Sprintf("%s:%s", ecosystem, key))
			}

			return nil
		}); err != nil {
			errCh <- errors.WithStack(err)
		}
	}()

	return resCh, errCh
}

type vulnerabilityRoot struct {
	ID              string
	Advisories      [][]string
	Vulnerabilities [][]string
	Detections      [][]string
	DataSources     []string
}

func (c *Connection) GetVulnerabilityData(id string) (*types.VulnerabilityData, error) {
	roots := vulnerabilityRoot{ID: id}

	if err := c.conn.View(func(tx *bolt.Tx) error {
		vb := tx.Bucket([]byte("vulnerability"))
		if vb == nil {
			return errors.Errorf("bucket:%q is not exists", "vulnerability")
		}

		vrb := vb.Bucket([]byte("root"))
		if vrb == nil {
			return errors.Errorf("bucket:%q is not exists", "vulnerability:root")
		}

		var root dbTypes.VulnerabilityRoot
		if bs := vrb.Get([]byte(id)); len(bs) > 0 {
			if err := util.Unmarshal(bs, &root); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability:root:%s", id))
			}
		}

		vab := vb.Bucket([]byte("advisory"))
		if vab == nil {
			return errors.Errorf("bucket:%q is not exists", "vulnerability:advisory")
		}
		if vaab := vab.Bucket([]byte(id)); vaab != nil && !slices.Contains(root.Advisories, id) {
			root.Advisories = append(root.Advisories, id)
		}
		for _, a := range root.Advisories {
			keys, err := getVulnerabilityKeys(vab, a)
			if err != nil {
				return errors.Wrapf(err, "get advisory keys for %q", a)
			}
			for _, key := range keys {
				if !slices.ContainsFunc(roots.Advisories, func(e []string) bool {
					return slices.Equal(e, key)
				}) {
					roots.Advisories = append(roots.Advisories, key)
				}
			}
		}

		vvb := vb.Bucket([]byte("vulnerability"))
		if vvb == nil {
			return errors.Errorf("bucket:%q is not exists", "vulnerability:vulnerability")
		}
		if vvvb := vvb.Bucket([]byte(id)); vvvb != nil && !slices.Contains(root.Vulnerabilities, id) {
			root.Vulnerabilities = append(root.Vulnerabilities, id)
		}
		for _, v := range root.Vulnerabilities {
			keys, err := getVulnerabilityKeys(vvb, v)
			if err != nil {
				return errors.Wrapf(err, "get vulnerability keys for %q", v)
			}
			for _, key := range keys {
				if !slices.ContainsFunc(roots.Vulnerabilities, func(e []string) bool {
					return slices.Equal(e, key)
				}) {
					roots.Vulnerabilities = append(roots.Vulnerabilities, key)
				}
			}
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}

	var ds [][]string
	for _, qs := range append(roots.Advisories, roots.Vulnerabilities...) {
		if len(qs) != 3 {
			return nil, errors.Errorf("unexpected queries. expected: %q, actual: %q", []string{"<Advisory ID | CVE ID>", "<Source ID>", "<Root ID>"}, qs)
		}

		if slices.ContainsFunc(roots.Detections, func(e []string) bool {
			return slices.Equal(e[:2], []string{qs[2], qs[1]})
		}) {
			continue
		}

		if !slices.ContainsFunc(ds, func(e []string) bool {
			return slices.Equal(e, []string{qs[2], qs[1]})
		}) {
			ds = append(ds, []string{qs[2], qs[1]})
		}

		if !slices.Contains(roots.DataSources, qs[1]) {
			roots.DataSources = append(roots.DataSources, qs[1])
		}
	}

	if err := c.conn.View(func(tx *bolt.Tx) error {
		db := tx.Bucket([]byte("detection"))
		if db == nil {
			return errors.Errorf("bucket:%q is not exists", "detection")
		}

		for _, qs := range ds {
			if len(qs) != 2 {
				return errors.Errorf("unexpected detection prefix queries. expected: %q, actual: %q", []string{"<Root ID>", "<Source ID>"}, qs)
			}

			drb := db.Bucket([]byte(qs[0]))
			if drb == nil {
				continue
			}

			drsb := drb.Bucket([]byte(qs[1]))
			if drsb == nil {
				continue
			}

			if err := drsb.ForEach(func(k, _ []byte) error {
				if !slices.ContainsFunc(roots.Detections, func(e []string) bool {
					return slices.Equal(e, []string{qs[0], qs[1], string(k)})
				}) {
					roots.Detections = append(roots.Detections, []string{qs[0], qs[1], string(k)})
				}
				return nil
			}); err != nil {
				return errors.Wrapf(err, "walk %s", fmt.Sprintf("detection:%s:%s", qs[0], qs[1]))
			}
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}

	return c.getVulnerabilityData(roots)
}

func getVulnerabilityKeys(vnb *bolt.Bucket, id string) ([][]string, error) {
	var keys [][]string

	vnnb := vnb.Bucket([]byte(id))
	if vnnb != nil {
		if err := vnnb.ForEachBucket(func(sk []byte) error {
			vnnsb := vnnb.Bucket(sk)
			if vnnsb == nil {
				return errors.Errorf("bucket:%q is not exists", fmt.Sprintf("%s:%s", id, sk))
			}

			if err := vnnsb.ForEach(func(rk, _ []byte) error {
				keys = append(keys, []string{id, string(sk), string(rk)})
				return nil
			}); err != nil {
				return errors.Wrapf(err, "walk %s", fmt.Sprintf("%s:%s", id, sk))
			}
			return nil
		}); err != nil {
			return nil, errors.Wrapf(err, "walk %s", id)
		}
	}

	return keys, nil
}

func (c *Connection) getVulnerabilityData(root vulnerabilityRoot) (*types.VulnerabilityData, error) {
	var data types.VulnerabilityData
	if err := c.conn.View(func(tx *bolt.Tx) error {
		vb := tx.Bucket([]byte("vulnerability"))
		if vb == nil {
			return errors.Errorf("bucket:%q is not exists", "vulnerability")
		}

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

			var a advisoryTypes.Advisory
			if err := util.Unmarshal(vaasb.Get([]byte(qs[2])), &a); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability:advisory:%s:%s:%s", qs[0], qs[1], qs[2]))
			}

			da, ok := am[a.Content.ID]
			if !ok {
				da = types.VulnerabilityDataAdvisory{
					ID:       a.Content.ID,
					Contents: map[sourceTypes.SourceID]map[string][]advisoryTypes.Advisory{},
				}
			}
			dac, ok := da.Contents[sourceTypes.SourceID(qs[1])]
			if !ok {
				dac = map[string][]advisoryTypes.Advisory{}
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

			var v vulnerabilityTypes.Vulnerability
			if err := util.Unmarshal(vvvsb.Get([]byte(qs[2])), &v); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability:vulnerability:%s:%s:%s", qs[0], qs[1], qs[2]))
			}

			dv, ok := vm[v.Content.ID]
			if !ok {
				dv = types.VulnerabilityDataVulnerability{
					ID:       v.Content.ID,
					Contents: map[sourceTypes.SourceID]map[string][]vulnerabilityTypes.Vulnerability{},
				}
			}
			dvc, ok := dv.Contents[sourceTypes.SourceID(qs[1])]
			if !ok {
				dvc = map[string][]vulnerabilityTypes.Vulnerability{}
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
			if len(qs) != 3 {
				return errors.Errorf("unexpected detection queries. expected: %q, actual: %q", []string{"<Root ID>", "<Source ID>", "<Ecosystem>"}, qs)
			}

			db := tx.Bucket([]byte("detection"))
			if db == nil {
				return errors.Errorf("bucket:%q is not exists", "detection")
			}

			drb := db.Bucket([]byte(qs[0]))
			if drb == nil {
				return errors.Errorf("bucket:%q is not exists", fmt.Sprintf("detection:%s", qs[0]))
			}

			drsb := drb.Bucket([]byte(qs[1]))
			if drsb == nil {
				return errors.Errorf("bucket:%q is not exists", fmt.Sprintf("detection:%s:%s", qs[0], qs[1]))
			}

			var ca criteriaTypes.Criteria
			if err := util.Unmarshal(drsb.Get([]byte(qs[2])), &ca); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("detection:%s:%s:%s", qs[0], qs[1], qs[2]))
			}

			dd, ok := dm[detectionTypes.Ecosystem(qs[2])]
			if !ok {
				dd = types.VulnerabilityDataDetection{
					Ecosystem: detectionTypes.Ecosystem(qs[2]),
					Contents:  map[sourceTypes.SourceID]map[string]criteriaTypes.Criteria{},
				}
			}
			ddc, ok := dd.Contents[sourceTypes.SourceID(qs[1])]
			if !ok {
				ddc = map[string]criteriaTypes.Criteria{}
			}
			ddc[qs[0]] = ca
			dd.Contents[sourceTypes.SourceID(qs[1])] = ddc
			dm[detectionTypes.Ecosystem(qs[2])] = dd
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
			if err := util.Unmarshal(sb.Get([]byte(q)), &d); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("datasource:%s", q))
			}

			if !slices.ContainsFunc(data.DataSources, func(e datasourceTypes.DataSource) bool {
				return e.ID == d.ID
			}) {
				data.DataSources = append(data.DataSources, d)
			}
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return &data, nil
}

func (c *Connection) PutVulnerabilityData(root string) error {
	if err := c.conn.Update(func(tx *bolt.Tx) error {
		roots := map[string]dbTypes.VulnerabilityRoot{}
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

			roots[data.ID] = dbTypes.VulnerabilityRoot{
				ID:          data.ID,
				DataSources: []string{string(data.DataSource)},
			}

			if err := putDetection(tx, data); err != nil {
				return errors.Wrap(err, "put detection")
			}

			if err := putAdvisory(tx, data, roots); err != nil {
				return errors.Wrap(err, "put advisory")
			}

			if err := putVulnerability(tx, data, roots); err != nil {
				return errors.Wrap(err, "put vulnerability")
			}

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", root)
		}

		for _, root := range roots {
			if err := putRoot(tx, root); err != nil {
				return errors.Wrap(err, "put root")
			}
		}

		return nil
	}); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func putDetection(tx *bolt.Tx, data dataTypes.Data) error {
	db, err := tx.CreateBucketIfNotExists([]byte("detection"))
	if err != nil {
		return errors.Wrapf(err, "create bucket:%q if not exists", "detection")
	}

	drb, err := db.CreateBucketIfNotExists([]byte(data.ID))
	if err != nil {
		return errors.Wrapf(err, "create bucket:%q if not exists", fmt.Sprintf("detection:%s", data.ID))
	}

	drsb, err := drb.CreateBucketIfNotExists([]byte(data.DataSource))
	if err != nil {
		return errors.Wrapf(err, "create bucket:%q if not exists", fmt.Sprintf("detection:%s:%s", data.ID, data.DataSource))
	}

	for _, d := range data.Detection {
		bs, err := util.Marshal(d.Criteria)
		if err != nil {
			return errors.Wrap(err, "marshal criteria")
		}

		if err := drsb.Put([]byte(d.Ecosystem), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("detection:%s:%s:%s", data.ID, data.DataSource, d.Ecosystem))
		}

		pkgs := walkCriteria(d.Criteria)
		slices.Sort(pkgs)
		pkgs = slices.Compact(pkgs)

		eb, err := tx.CreateBucketIfNotExists([]byte(d.Ecosystem))
		if err != nil {
			return errors.Wrapf(err, "create bucket:%q if not exists", d.Ecosystem)
		}
		for _, p := range pkgs {
			epb, err := eb.CreateBucketIfNotExists([]byte(p))
			if err != nil {
				return errors.Wrapf(err, "create bucket:%q if not exists", fmt.Sprintf("%s:%s", d.Ecosystem, p))
			}

			eprb, err := epb.CreateBucketIfNotExists([]byte(data.ID))
			if err != nil {
				return errors.Wrapf(err, "create bucket:%q if not exists", fmt.Sprintf("%s:%s:%s", d.Ecosystem, p, data.ID))
			}

			bs, err := util.Marshal([]string{data.ID, string(data.DataSource), string(d.Ecosystem)})
			if err != nil {
				return errors.Wrap(err, "marshal criteria key")
			}

			if err := eprb.Put([]byte(data.DataSource), bs); err != nil {
				return errors.Wrapf(err, "put %s", fmt.Sprintf("%s:%s:%s:%s", d.Ecosystem, p, data.ID, data.DataSource))
			}
		}
	}

	return nil
}

func walkCriteria(ca criteriaTypes.Criteria) []string {
	var pkgs []string

	for _, ca := range ca.Criterias {
		pkgs = append(pkgs, walkCriteria(ca)...)
	}

	for _, co := range ca.Criterions {
		if !co.Vulnerable {
			continue
		}

		if co.Package.Name != "" {
			pkgs = append(pkgs, co.Package.Name)
		}
		if co.Package.CPE != "" {
			wfn, err := naming.UnbindFS(co.Package.CPE)
			if err != nil {
				slog.Warn("failed to unbind a formatted string to WFN", "input", co.Package.CPE)
				continue
			}
			pkgs = append(pkgs, fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct)))
		}
	}

	return pkgs
}

func putAdvisory(tx *bolt.Tx, data dataTypes.Data, roots map[string]dbTypes.VulnerabilityRoot) error {
	vb, err := tx.CreateBucketIfNotExists([]byte("vulnerability"))
	if err != nil {
		return errors.Wrapf(err, "create bucket:%q if not exists", "vulnerability")
	}

	vab, err := vb.CreateBucketIfNotExists([]byte("advisory"))
	if err != nil {
		return errors.Wrapf(err, "create bucket:%q if not exists", "vulnerability:advisory")
	}
	for _, a := range data.Advisories {
		vaab, err := vab.CreateBucketIfNotExists([]byte(a.Content.ID))
		if err != nil {
			return errors.Wrapf(err, "create bucket:%q if not exists", fmt.Sprintf("vulnerability:advisory:%s", a.Content.ID))
		}

		vaasb, err := vaab.CreateBucketIfNotExists([]byte(data.DataSource))
		if err != nil {
			return errors.Wrapf(err, "create bucket:%q if not exists", fmt.Sprintf("vulnerability:advisory:%s:%s", a.Content.ID, data.DataSource))
		}

		bs, err := util.Marshal(a)
		if err != nil {
			return errors.Wrap(err, "marshal advisory")
		}

		if err := vaasb.Put([]byte(data.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("vulnerability:advisory:%s:%s:%s", a.Content.ID, data.DataSource, data.ID))
		}

		r := roots[data.ID]
		r.Advisories = append(r.Advisories, a.Content.ID)
		roots[data.ID] = r
	}

	return nil
}

func putVulnerability(tx *bolt.Tx, data dataTypes.Data, roots map[string]dbTypes.VulnerabilityRoot) error {
	vb, err := tx.CreateBucketIfNotExists([]byte("vulnerability"))
	if err != nil {
		return errors.Wrapf(err, "create bucket:%q if not exists", "vulnerability")
	}

	vvb, err := vb.CreateBucketIfNotExists([]byte("vulnerability"))
	if err != nil {
		return errors.Wrapf(err, "create bucket:%q if not exists", "vulnerability:vulnerability")
	}
	for _, v := range data.Vulnerabilities {
		vvvb, err := vvb.CreateBucketIfNotExists([]byte(v.Content.ID))
		if err != nil {
			return errors.Wrapf(err, "create bucket:%q if not exists", fmt.Sprintf("vulnerability:vulnerability:%s", v.Content.ID))
		}

		vvvsb, err := vvvb.CreateBucketIfNotExists([]byte(data.DataSource))
		if err != nil {
			return errors.Wrapf(err, "create bucket:%q if not exists", fmt.Sprintf("vulnerability:vulnerability:%s:%s", v.Content.ID, data.DataSource))
		}

		bs, err := util.Marshal(v)
		if err != nil {
			return errors.Wrap(err, "marshal vulnerability")
		}

		if err := vvvsb.Put([]byte(data.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("vulnerability:vulnerability:%s:%s:%s", v.Content.ID, data.DataSource, data.ID))
		}

		r := roots[data.ID]
		r.Vulnerabilities = append(r.Vulnerabilities, v.Content.ID)
		roots[data.ID] = r
	}

	return nil
}

func putRoot(tx *bolt.Tx, root dbTypes.VulnerabilityRoot) error {
	vb := tx.Bucket([]byte("vulnerability"))
	if vb == nil {
		return errors.Errorf("bucket:%q is not exists", "vulnerability")
	}

	vrb, err := vb.CreateBucketIfNotExists([]byte("root"))
	if err != nil {
		return errors.Wrapf(err, "create bucket:%q if not exists", "vulnerability:root")
	}

	if bs := vrb.Get([]byte(root.ID)); len(bs) > 0 {
		var r dbTypes.VulnerabilityRoot
		if err := util.Unmarshal(bs, &r); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability:root:%s", r.ID))
		}
		for _, a := range r.Advisories {
			if !slices.Contains(root.Advisories, a) {
				r.Advisories = append(r.Advisories, a)
			}
		}
		for _, v := range r.Vulnerabilities {
			if !slices.Contains(root.Vulnerabilities, v) {
				r.Vulnerabilities = append(r.Vulnerabilities, v)
			}
		}
		for _, d := range r.DataSources {
			if !slices.Contains(root.DataSources, d) {
				root.DataSources = append(root.DataSources, d)
			}
		}
	}

	bs, err := util.Marshal(root)
	if err != nil {
		return errors.Wrap(err, "marshal root")
	}

	if err := vrb.Put([]byte(root.ID), bs); err != nil {
		return errors.Wrapf(err, "put %s", fmt.Sprintf("vulnerability:root:%s", root.ID))
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

		if err := util.Unmarshal(sb.Get([]byte(id)), &v); err != nil {
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

		bs, err := util.Marshal(datasource)
		if err != nil {
			return errors.Wrap(err, "marshal datasource")
		}

		if err := sb.Put([]byte(datasource.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("datasource:%s", datasource.ID))
		}

		return nil
	})
}

func (c *Connection) DeleteAll() error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		var ns [][]byte
		if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			ns = append(ns, name)
			return nil
		}); err != nil {
			return errors.Wrap(err, "foreach root")
		}

		for _, n := range ns {
			if err := tx.DeleteBucket(n); err != nil {
				return errors.Wrapf(err, "delete bucket:%q", n)
			}
		}

		return nil
	})
}
