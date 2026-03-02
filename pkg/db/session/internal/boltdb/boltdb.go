package boltdb

import (
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/util"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/MaineK00n/vuls2/pkg/version"
)

const (
	SchemaVersion = 1
)

// boltdb: metadata:db -> dbTypes.Metadata

// boltdb: vulnerability:root:<Root ID> -> vulnerabilityRoot

// boltdb: vulnerability:advisory:<Advisory ID> -> map[<Source ID>][<Root ID>][]advisoryTypes.Advisory

// boltdb: vulnerability:vulnerability:<CVE ID> -> map[<Source ID>][<Root ID>][]vulnerabilityTypes.Vulnerability

// boltdb: <ecosystem>:index:<package> -> [<Root ID>]

// boltdb: <ecosystem>:detection:<Root ID> -> map[<Source ID>]criteriaTypes.Criteria

// boltdb: datasource:<Source ID> -> datasourceTypes.DataSource

type Config struct {
	Path string

	Options *bolt.Options
}

type Connection struct {
	Config *Config

	conn *bolt.DB
}

func (c *Connection) Open() error {
	if c.Config == nil {
		return errors.New("connection config is not set")
	}

	db, err := bolt.Open(c.Config.Path, 0600, c.Config.Options)
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
		mb := tx.Bucket([]byte("metadata"))
		if mb == nil {
			return errors.Errorf("%q is not exists", "metadata")
		}

		bs := mb.Get([]byte("db"))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundMetadata, "%q not found", "metadata -> db")
		}

		if err := util.UnmarshalPB(bs, &v); err != nil {
			return errors.Wrapf(err, "unmarshal %q", "metadata -> db")
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return &v, nil
}

func (c *Connection) PutMetadata(metadata dbTypes.Metadata) error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		if err := putMetadata(tx, metadata); err != nil {
			return errors.Wrap(err, "put metadata")
		}
		return nil
	})
}

func putMetadata(tx *bolt.Tx, metadata dbTypes.Metadata) error {
	mb := tx.Bucket([]byte("metadata"))
	if mb == nil {
		return errors.Errorf("%q is not exists", "metadata")
	}

	bs, err := util.MarshalPB(metadata)
	if err != nil {
		return errors.Wrap(err, "marshal metadata")
	}

	if err := mb.Put([]byte("db"), bs); err != nil {
		return errors.Wrapf(err, "put %q", "metadata -> db")
	}

	return nil
}

func (c *Connection) Put(root string) error {
	if err := c.conn.Update(func(tx *bolt.Tx) error {
		if err := func() error {
			if err := filepath.WalkDir(filepath.Join(root, "data"), func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() || filepath.Ext(path) != ".json" {
					return nil
				}

				f, err := os.Open(path)
				if err != nil {
					return errors.Wrapf(err, "open %s", path)
				}
				defer f.Close()

				var data dataTypes.Data
				if err := json.UnmarshalRead(f, &data); err != nil {
					return errors.Wrapf(err, "unmarshal %s", path)
				}

				if err := putDetection(tx, data); err != nil {
					return errors.Wrap(err, "put detection")
				}

				if err := putAdvisory(tx, data); err != nil {
					return errors.Wrap(err, "put advisory")
				}

				if err := putVulnerability(tx, data); err != nil {
					return errors.Wrap(err, "put vulnerability")
				}

				if err := putRoot(tx, data); err != nil {
					return errors.Wrap(err, "put root")
				}

				return nil
			}); err != nil {
				return errors.Wrapf(err, "walk %s", root)
			}

			return nil
		}(); err != nil {
			return errors.Wrap(err, "put vulnerability data")
		}

		if err := func() error {
			f, err := os.Open(filepath.Join(root, "datasource.json"))
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(root, "datasource.json"))
			}
			defer f.Close()

			var ds datasourceTypes.DataSource
			if err := json.UnmarshalRead(f, &ds); err != nil {
				return errors.Wrapf(err, "unmarshal %s", filepath.Join(root, "datasource.json"))
			}

			if err := putDataSource(tx, ds); err != nil {
				return errors.Wrap(err, "put data source")
			}

			return nil
		}(); err != nil {
			return errors.Wrap(err, "put data source")
		}

		if err := putMetadata(tx, dbTypes.Metadata{
			SchemaVersion: SchemaVersion,
			CreatedBy:     version.String(),
			LastModified:  time.Now().UTC(),
		}); err != nil {
			return errors.Wrap(err, "put metadata")
		}

		return nil
	}); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func putDetection(tx *bolt.Tx, data dataTypes.Data) error {
	for _, d := range data.Detections {
		eb, err := tx.CreateBucketIfNotExists([]byte(d.Ecosystem))
		if err != nil {
			return errors.Wrapf(err, "create %q if not exists", d.Ecosystem)
		}

		edb, err := eb.CreateBucketIfNotExists([]byte("detection"))
		if err != nil {
			return errors.Wrapf(err, "create %q if not exists", fmt.Sprintf("%s -> detection", d.Ecosystem))
		}

		m := make(map[sourceTypes.SourceID][]conditionTypes.Condition)
		if bs := edb.Get([]byte(data.ID)); len(bs) > 0 {
			if err := util.UnmarshalPB(bs, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("%s -> detection -> %s", d.Ecosystem, data.ID))
			}
		}
		m[data.DataSource.ID] = d.Conditions

		bs, err := util.MarshalPB(m)
		if err != nil {
			return errors.Wrap(err, "marshal conditions map")
		}

		if err := edb.Put([]byte(data.ID), bs); err != nil {
			return errors.Wrapf(err, "put %q", fmt.Sprintf("%s -> detection -> %s", d.Ecosystem, data.ID))
		}

		eib, err := eb.CreateBucketIfNotExists([]byte("index"))
		if err != nil {
			return errors.Wrapf(err, "create %q if not exists", fmt.Sprintf("%s -> index", d.Ecosystem))
		}

		var pkgs []string
		for _, cond := range d.Conditions {
			ps, err := util.WalkCriteria(cond.Criteria)
			if err != nil {
				return errors.Wrap(err, "walk criteria")
			}
			pkgs = append(pkgs, ps...)
		}
		slices.Sort(pkgs)

		for _, p := range slices.Compact(pkgs) {
			var rootIDs []dataTypes.RootID
			if bs := eib.Get([]byte(p)); len(bs) > 0 {
				if err := util.UnmarshalPB(bs, &rootIDs); err != nil {
					return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("%s -> index -> %s", d.Ecosystem, p))
				}
			}
			if !slices.Contains(rootIDs, data.ID) {
				rootIDs = append(rootIDs, data.ID)
			}

			bs, err := util.MarshalPB(rootIDs)
			if err != nil {
				return errors.Wrap(err, "marshal root IDs")
			}

			if err := eib.Put([]byte(p), bs); err != nil {
				return errors.Wrapf(err, "put %q", fmt.Sprintf("%s -> index -> %s", d.Ecosystem, p))
			}
		}
	}

	return nil
}

func putAdvisory(tx *bolt.Tx, data dataTypes.Data) error {
	vb := tx.Bucket([]byte("vulnerability"))
	if vb == nil {
		return errors.Errorf("%q is not exists", "vulnerability")
	}

	vab := vb.Bucket([]byte("advisory"))
	if vab == nil {
		return errors.Errorf("%q is not exists", "vulnerability -> advisory")
	}

	for _, a := range data.Advisories {
		m := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory)
		if bs := vab.Get([]byte(a.Content.ID)); len(bs) > 0 {
			if err := util.UnmarshalPB(bs, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> advisory -> %s", a.Content.ID))
			}
		}
		if m[data.DataSource.ID] == nil {
			m[data.DataSource.ID] = make(map[dataTypes.RootID][]advisoryTypes.Advisory)
		}
		m[data.DataSource.ID][data.ID] = append(m[data.DataSource.ID][data.ID], a)

		bs, err := util.MarshalPB(m)
		if err != nil {
			return errors.Wrap(err, "marshal advisory map")
		}

		if err := vab.Put([]byte(a.Content.ID), bs); err != nil {
			return errors.Wrapf(err, "put %q", fmt.Sprintf("vulnerability -> advisory -> %s", a.Content.ID))
		}
	}

	return nil
}

func putVulnerability(tx *bolt.Tx, data dataTypes.Data) error {
	vb := tx.Bucket([]byte("vulnerability"))
	if vb == nil {
		return errors.Errorf("%q is not exists", "vulnerability")
	}

	vvb := vb.Bucket([]byte("vulnerability"))
	if vvb == nil {
		return errors.Errorf("%q is not exists", "vulnerability -> vulnerability")
	}

	for _, v := range data.Vulnerabilities {
		m := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
		if bs := vvb.Get([]byte(v.Content.ID)); len(bs) > 0 {
			if err := util.UnmarshalPB(bs, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> vulnerability -> %s", v.Content.ID))
			}
		}
		if m[data.DataSource.ID] == nil {
			m[data.DataSource.ID] = make(map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
		}
		m[data.DataSource.ID][data.ID] = append(m[data.DataSource.ID][data.ID], v)

		bs, err := util.MarshalPB(m)
		if err != nil {
			return errors.Wrap(err, "marshal vulnerability map")
		}

		if err := vvb.Put([]byte(v.Content.ID), bs); err != nil {
			return errors.Wrapf(err, "put %q", fmt.Sprintf("vulnerability -> vulnerability -> %s", v.Content.ID))
		}
	}

	return nil
}

func putRoot(tx *bolt.Tx, data dataTypes.Data) error {
	root := vulnerabilityRoot{
		ID: data.ID,
		Advisories: func() []advisoryContentTypes.AdvisoryID {
			as := make([]advisoryContentTypes.AdvisoryID, 0, len(data.Advisories))
			for _, a := range data.Advisories {
				as = append(as, a.Content.ID)
			}
			return as
		}(),
		Vulnerabilities: func() []vulnerabilityContentTypes.VulnerabilityID {
			vs := make([]vulnerabilityContentTypes.VulnerabilityID, 0, len(data.Vulnerabilities))
			for _, v := range data.Vulnerabilities {
				vs = append(vs, v.Content.ID)
			}
			return vs
		}(),
		Ecosystems: func() []ecosystemTypes.Ecosystem {
			es := make([]ecosystemTypes.Ecosystem, 0, len(data.Detections))
			for _, d := range data.Detections {
				es = append(es, d.Ecosystem)
			}
			return es
		}(),
		DataSources: []sourceTypes.SourceID{data.DataSource.ID},
	}

	vb := tx.Bucket([]byte("vulnerability"))
	if vb == nil {
		return errors.Errorf("%q is not exists", "vulnerability")
	}

	vrb := vb.Bucket([]byte("root"))
	if vrb == nil {
		return errors.Errorf("%q is not exists", "vulnerability -> root")
	}

	if bs := vrb.Get([]byte(root.ID)); len(bs) > 0 {
		var rd util.VulnerabilityRootData
		if err := util.UnmarshalPB(bs, &rd); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> root -> %s", root.ID))
		}
		r := vulnerabilityRoot{
			ID:              rd.ID,
			Advisories:      rd.Advisories,
			Vulnerabilities: rd.Vulnerabilities,
			Ecosystems:      rd.Ecosystems,
			DataSources:     rd.DataSources,
		}

		for _, a := range r.Advisories {
			if !slices.Contains(root.Advisories, a) {
				root.Advisories = append(root.Advisories, a)
			}
		}
		for _, v := range r.Vulnerabilities {
			if !slices.Contains(root.Vulnerabilities, v) {
				root.Vulnerabilities = append(root.Vulnerabilities, v)
			}
		}
		for _, e := range r.Ecosystems {
			if !slices.Contains(root.Ecosystems, e) {
				root.Ecosystems = append(root.Ecosystems, e)
			}
		}
		for _, d := range r.DataSources {
			if !slices.Contains(root.DataSources, d) {
				root.DataSources = append(root.DataSources, d)
			}
		}
	}

	bs, err := util.MarshalPB(util.VulnerabilityRootData{
		ID:              root.ID,
		Advisories:      root.Advisories,
		Vulnerabilities: root.Vulnerabilities,
		Ecosystems:      root.Ecosystems,
		DataSources:     root.DataSources,
	})
	if err != nil {
		return errors.Wrap(err, "marshal root")
	}

	if err := vrb.Put([]byte(root.ID), bs); err != nil {
		return errors.Wrapf(err, "put %q", fmt.Sprintf("vulnerability -> root -> %s", root.ID))
	}

	return nil
}

func putDataSource(tx *bolt.Tx, datasource datasourceTypes.DataSource) error {
	sb := tx.Bucket([]byte("datasource"))
	if sb == nil {
		return errors.Errorf("%q is not exists", "datasource")
	}

	if sb.Get([]byte(datasource.ID)) != nil {
		return errors.Errorf("%q already exists", fmt.Sprintf("datasource -> %s", datasource.ID))
	}

	bs, err := util.MarshalPB(datasource)
	if err != nil {
		return errors.Wrap(err, "marshal datasource")
	}

	if err := sb.Put([]byte(datasource.ID), bs); err != nil {
		return errors.Wrapf(err, "put %q", fmt.Sprintf("datasource -> %q", datasource.ID))
	}

	return nil
}

func (c *Connection) GetRoot(id dataTypes.RootID) (dbTypes.VulnerabilityData, error) {
	var d dbTypes.VulnerabilityData
	if err := c.conn.View(func(tx *bolt.Tx) error {
		vb := tx.Bucket([]byte("vulnerability"))
		if vb == nil {
			return errors.Errorf("%q is not exists", "vulnerability")
		}

		vrb := vb.Bucket([]byte("root"))
		if vrb == nil {
			return errors.Errorf("%q is not exists", "vulnerability -> root")
		}

		bs := vrb.Get([]byte(id))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundRoot, "%q not found", fmt.Sprintf("vulnerability -> root -> %s", id))
		}

		var rd util.VulnerabilityRootData
		if err := util.UnmarshalPB(bs, &rd); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> root -> %s", id))
		}
		r := vulnerabilityRoot{
			ID:              rd.ID,
			Advisories:      rd.Advisories,
			Vulnerabilities: rd.Vulnerabilities,
			Ecosystems:      rd.Ecosystems,
			DataSources:     rd.DataSources,
		}

		d = dbTypes.VulnerabilityData{
			ID: string(r.ID),
			Advisories: func() []dbTypes.VulnerabilityDataAdvisory {
				as := make([]dbTypes.VulnerabilityDataAdvisory, 0, len(r.Advisories))
				for _, a := range r.Advisories {
					as = append(as, dbTypes.VulnerabilityDataAdvisory{ID: a})
				}
				return as
			}(),
			Vulnerabilities: func() []dbTypes.VulnerabilityDataVulnerability {
				vs := make([]dbTypes.VulnerabilityDataVulnerability, 0, len(r.Vulnerabilities))
				for _, v := range r.Vulnerabilities {
					vs = append(vs, dbTypes.VulnerabilityDataVulnerability{ID: v})
				}
				return vs
			}(),
			Detections: func() []dbTypes.VulnerabilityDataDetection {
				ds := make([]dbTypes.VulnerabilityDataDetection, 0, len(r.Ecosystems))
				for _, e := range r.Ecosystems {
					ds = append(ds, dbTypes.VulnerabilityDataDetection{Ecosystem: e})
				}
				return ds
			}(),
			DataSources: func() []datasourceTypes.DataSource {
				ds := make([]datasourceTypes.DataSource, 0, len(r.DataSources))
				for _, d := range r.DataSources {
					ds = append(ds, datasourceTypes.DataSource{ID: d})
				}
				return ds
			}(),
		}

		return nil
	}); err != nil {
		return dbTypes.VulnerabilityData{}, errors.WithStack(err)
	}
	return d, nil
}

func (c *Connection) GetAdvisory(id advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error) {
	var m map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
	if err := c.conn.View(func(tx *bolt.Tx) error {
		vb := tx.Bucket([]byte("vulnerability"))
		if vb == nil {
			return errors.Errorf("%q is not exists", "vulnerability")
		}

		vab := vb.Bucket([]byte("advisory"))
		if vab == nil {
			return errors.Errorf("%q is not exists", "vulnerability -> advisory")
		}

		bs := vab.Get([]byte(id))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundAdvisory, "%q not found", fmt.Sprintf("vulnerability -> advisory -> %s", id))
		}

		if err := util.UnmarshalPB(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> advisory -> %s", id))
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
}

func (c *Connection) GetVulnerability(id vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error) {
	var m map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
	if err := c.conn.View(func(tx *bolt.Tx) error {
		vb := tx.Bucket([]byte("vulnerability"))
		if vb == nil {
			return errors.Errorf("%q is not exists", "vulnerability")
		}

		vvb := vb.Bucket([]byte("vulnerability"))
		if vvb == nil {
			return errors.Errorf("%q is not exists", "vulnerability -> vulnerability")
		}

		bs := vvb.Get([]byte(id))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundVulnerability, "%q not found", fmt.Sprintf("vulnerability -> vulnerability -> %s", id))
		}

		if err := util.UnmarshalPB(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> vulnerability -> %s", id))
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
}

func (c *Connection) GetEcosystems() ([]ecosystemTypes.Ecosystem, error) {
	var es []ecosystemTypes.Ecosystem
	if err := c.conn.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			switch n := string(name); n {
			case "metadata", "vulnerability", "datasource":
			default:
				es = append(es, ecosystemTypes.Ecosystem(name))
			}
			return nil
		})
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return es, nil
}

func (c *Connection) GetIndex(ecosystem ecosystemTypes.Ecosystem, query string) ([]dataTypes.RootID, error) {
	var rootIDs []dataTypes.RootID
	if err := c.conn.View(func(tx *bolt.Tx) error {
		eb := tx.Bucket([]byte(ecosystem))
		if eb == nil {
			return errors.Wrapf(dbTypes.ErrNotFoundEcosystem, "%q not found", ecosystem)
		}

		eib := eb.Bucket([]byte("index"))
		if eib == nil {
			return errors.Errorf("%q is not exists", fmt.Sprintf("%s -> index", ecosystem))
		}

		bs := eib.Get([]byte(query))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundIndex, "%q not found", fmt.Sprintf("%s -> index -> %s", ecosystem, query))
		}

		if err := util.UnmarshalPB(bs, &rootIDs); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("%s -> index -> %s", ecosystem, query))
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return rootIDs, nil
}

func (c *Connection) GetDetection(ecosystem ecosystemTypes.Ecosystem, rootID dataTypes.RootID) (map[sourceTypes.SourceID][]conditionTypes.Condition, error) {
	var m map[sourceTypes.SourceID][]conditionTypes.Condition
	if err := c.conn.View(func(tx *bolt.Tx) error {
		eb := tx.Bucket([]byte(ecosystem))
		if eb == nil {
			return errors.Wrapf(dbTypes.ErrNotFoundEcosystem, "%q not found", ecosystem)
		}

		edb := eb.Bucket([]byte("detection"))
		if edb == nil {
			return errors.Errorf("%q is not exists", fmt.Sprintf("%s -> detection", ecosystem))
		}

		bs := edb.Get([]byte(rootID))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundDetection, "%q not found", fmt.Sprintf("%s -> detection -> %s", ecosystem, rootID))
		}

		if err := util.UnmarshalPB(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("%s -> detection -> %s", ecosystem, rootID))
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
}

func (c *Connection) GetDataSources() ([]datasourceTypes.DataSource, error) {
	var ds []datasourceTypes.DataSource
	if err := c.conn.View(func(tx *bolt.Tx) error {
		sb := tx.Bucket([]byte("datasource"))
		if sb == nil {
			return errors.Errorf("%q is not exists", "datasource")
		}

		return sb.ForEach(func(k, v []byte) error {
			var d datasourceTypes.DataSource
			if err := util.UnmarshalPB(v, &d); err != nil {
				return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("datasource -> %s", k))
			}
			ds = append(ds, d)
			return nil
		})
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return ds, nil
}

func (c *Connection) GetDataSource(id sourceTypes.SourceID) (datasourceTypes.DataSource, error) {
	var v datasourceTypes.DataSource
	if err := c.conn.View(func(tx *bolt.Tx) error {
		sb := tx.Bucket([]byte("datasource"))
		if sb == nil {
			return errors.Errorf("%q is not exists", "datasource")
		}

		bs := sb.Get([]byte(id))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundDataSource, "%q not found", fmt.Sprintf("datasource -> %s", id))
		}

		if err := util.UnmarshalPB(bs, &v); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("datasource -> %s", id))
		}

		return nil
	}); err != nil {
		return datasourceTypes.DataSource{}, errors.WithStack(err)
	}
	return v, nil
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
				return errors.Wrapf(err, "delete %q", n)
			}
		}

		return nil
	})
}

func (c *Connection) Initialize() error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucket([]byte("metadata")); err != nil {
			return errors.Wrapf(err, "create %q", "metadata")
		}

		vb, err := tx.CreateBucket([]byte("vulnerability"))
		if err != nil {
			return errors.Wrapf(err, "create %q", "vulnerability")
		}

		if _, err := vb.CreateBucket([]byte("root")); err != nil {
			return errors.Wrapf(err, "create %q", "vulnerability -> root")
		}

		if _, err := vb.CreateBucket([]byte("advisory")); err != nil {
			return errors.Wrapf(err, "create %q", "vulnerability -> advisory")
		}

		if _, err := vb.CreateBucket([]byte("vulnerability")); err != nil {
			return errors.Wrapf(err, "create %q", "vulnerability -> vulnerability")
		}

		if _, err := tx.CreateBucket([]byte("datasource")); err != nil {
			return errors.Wrapf(err, "create %q", "datasource")
		}

		return nil
	})
}
