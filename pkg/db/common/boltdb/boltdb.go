package boltdb

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"slices"

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
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	"github.com/MaineK00n/vuls2/pkg/db/common/util"
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
	return c.conn.Close() //nolint:errcheck
}

func (c *Connection) GetMetadata() (*dbTypes.Metadata, error) {
	var v dbTypes.Metadata
	if err := c.conn.View(func(tx *bolt.Tx) error {
		mb := tx.Bucket([]byte("metadata"))
		if mb == nil {
			return errors.Errorf("bucket: %s is not exists", "metadata")
		}

		if err := util.Unmarshal(mb.Get([]byte("db")), &v); err != nil {
			return errors.Wrapf(err, "unmarshal %s", "metadata -> db")
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return &v, nil
}

func (c *Connection) PutMetadata(metadata dbTypes.Metadata) error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		mb := tx.Bucket([]byte("metadata"))
		if mb == nil {
			return errors.Errorf("bucket: %s is not exists", "metadata")
		}

		bs, err := util.Marshal(metadata)
		if err != nil {
			return errors.Wrap(err, "marshal metadata")
		}

		if err := mb.Put([]byte("db"), bs); err != nil {
			return errors.Wrapf(err, "put %s", "metadata -> db")
		}

		return nil
	})
}

func (c *Connection) GetVulnerabilityDetections(searchType dbTypes.SearchDetectionType, queries ...string) iter.Seq2[dbTypes.VulnerabilityDataDetection, error] {
	return func(yield func(dbTypes.VulnerabilityDataDetection, error) bool) {
		if err := c.conn.View(func(tx *bolt.Tx) error {
			switch searchType {
			case dbTypes.SearchDetectionPkg:
				if len(queries) != 2 {
					return errors.Errorf("unexpected pkg search queries. expected: %q, actual: %q", []string{"<ecosystem>", "<key>"}, queries)
				}

				eb := tx.Bucket([]byte(queries[0]))
				if eb == nil {
					return nil
				}

				eib := eb.Bucket([]byte("index"))
				if eib == nil {
					return errors.Errorf("bucket: %s is not exists", fmt.Sprintf("%s -> index", queries[0]))
				}

				bs := eib.Get([]byte(queries[1]))
				if len(bs) == 0 {
					return nil
				}

				var rootIDs []dataTypes.RootID
				if err := util.Unmarshal(bs, &rootIDs); err != nil {
					return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> index -> %s", queries[0], queries[1]))
				}

				edb := eb.Bucket([]byte("detection"))
				if edb == nil {
					return errors.Errorf("bucket: %s is not exists", fmt.Sprintf("%s -> detection", queries[0]))
				}

				for _, rootID := range rootIDs {
					var m map[sourceTypes.SourceID][]conditionTypes.Condition
					if err := util.Unmarshal(edb.Get([]byte(rootID)), &m); err != nil {
						return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> detection -> %s", queries[0], rootID))
					}

					if !yield(dbTypes.VulnerabilityDataDetection{
						Ecosystem: ecosystemTypes.Ecosystem(queries[0]),
						Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{rootID: m},
					}, nil) {
						return nil
					}
				}

				return nil
			case dbTypes.SearchDetectionRoot:
				if len(queries) != 1 {
					return errors.Errorf("unexpected root search queries. expected: %q, actual: %q", []string{"<root id>"}, queries)
				}
				ds, err := getDetection(tx, dataTypes.RootID(queries[0]))
				if err != nil {
					return errors.WithStack(err)
				}

				for _, d := range ds {
					if !yield(d, nil) {
						return nil
					}
				}

				return nil
			case dbTypes.SearchDetectionAdvisory:
				if len(queries) != 1 {
					return errors.Errorf("unexpected advisory search queries. expected: %q, actual: %q", []string{"<advisory id>"}, queries)
				}

				am, err := getAdvisory(tx, advisoryContentTypes.AdvisoryID(queries[0]))
				if err != nil {
					return errors.Wrap(err, "get advisory")
				}

				rootIDs := func() []dataTypes.RootID {
					var rs []dataTypes.RootID
					for _, mm := range am {
						for rootID := range mm {
							if !slices.Contains(rs, rootID) {
								rs = append(rs, rootID)
							}
						}
					}
					return rs
				}()

				em := make(map[ecosystemTypes.Ecosystem]map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition)
				for _, rootID := range rootIDs {
					ds, err := getDetection(tx, rootID)
					if err != nil {
						return errors.WithStack(err)
					}
					for _, d := range ds {
						if em[d.Ecosystem] == nil {
							em[d.Ecosystem] = make(map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition)
						}
						for rootID, cm := range d.Contents {
							em[d.Ecosystem][rootID] = cm
						}
					}
				}

				for ecosystem, m := range em {
					if !yield(dbTypes.VulnerabilityDataDetection{
						Ecosystem: ecosystem,
						Contents:  m,
					}, nil) {
						return nil
					}
				}

				return nil
			case dbTypes.SearchDetectionVulnerability:
				if len(queries) != 1 {
					return errors.Errorf("unexpected vulnerability search queries. expected: %q, actual: %q", []string{"<vulnerability id>"}, queries)
				}

				vm, err := getVulnerability(tx, vulnerabilityContentTypes.VulnerabilityID(queries[0]))
				if err != nil {
					return errors.Wrap(err, "get vulnerability")
				}

				rootIDs := func() []dataTypes.RootID {
					var rs []dataTypes.RootID
					for _, mm := range vm {
						for rootID := range mm {
							if !slices.Contains(rs, rootID) {
								rs = append(rs, rootID)
							}
						}
					}
					return rs
				}()

				em := make(map[ecosystemTypes.Ecosystem]map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition)
				for _, rootID := range rootIDs {
					ds, err := getDetection(tx, rootID)
					if err != nil {
						return errors.WithStack(err)
					}
					for _, d := range ds {
						if em[d.Ecosystem] == nil {
							em[d.Ecosystem] = make(map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition)
						}
						for rootID, cm := range d.Contents {
							em[d.Ecosystem][rootID] = cm
						}
					}
				}

				for ecosystem, m := range em {
					if !yield(dbTypes.VulnerabilityDataDetection{
						Ecosystem: ecosystem,
						Contents:  m,
					}, nil) {
						return nil
					}
				}

				return nil
			default:
				return errors.Errorf("unexpected search type. expected: %q, actual: %s", []dbTypes.SearchDetectionType{dbTypes.SearchDetectionPkg, dbTypes.SearchDetectionRoot, dbTypes.SearchDetectionAdvisory, dbTypes.SearchDetectionVulnerability}, searchType)
			}
		}); err != nil {
			if !yield(dbTypes.VulnerabilityDataDetection{}, errors.WithStack(err)) {
				return
			}
		}
	}
}

func (c *Connection) GetVulnerabilityData(searchType dbTypes.SearchDataType, id string) (*dbTypes.VulnerabilityData, error) {
	root := dbTypes.VulnerabilityData{ID: id}

	if err := c.conn.View(func(tx *bolt.Tx) error {
		switch searchType {
		case dbTypes.SearchDataRoot:
			r, err := getRoot(tx, dataTypes.RootID(id))
			if err != nil {
				return errors.Wrap(err, "get root")
			}
			if r.ID == "" {
				return nil
			}

			for _, a := range r.Advisories {
				m, err := getAdvisory(tx, a)
				if err != nil {
					return errors.Wrap(err, "get advisory")
				}
				if m == nil {
					return errors.Errorf("vulnerability -> advisory -> %s not found", a)
				}
				root.Advisories = append(root.Advisories, dbTypes.VulnerabilityDataAdvisory{
					ID:       a,
					Contents: m,
				})
			}

			for _, v := range r.Vulnerabilities {
				m, err := getVulnerability(tx, v)
				if err != nil {
					return errors.Wrap(err, "get vulnerability")
				}
				if m == nil {
					return errors.Errorf("vulnerability -> vulnerability -> %s not found", v)
				}
				root.Vulnerabilities = append(root.Vulnerabilities, dbTypes.VulnerabilityDataVulnerability{
					ID:       v,
					Contents: m,
				})
			}

			ds, err := getDetection(tx, dataTypes.RootID(id))
			if err != nil {
				return errors.Wrap(err, "get detection")
			}
			root.Detections = ds

			for _, datasource := range r.DataSources {
				ds, err := c.GetDataSource(sourceTypes.SourceID(datasource))
				if err != nil {
					return errors.Wrap(err, "get datasource")
				}
				root.DataSources = append(root.DataSources, *ds)
			}

			return nil
		case dbTypes.SearchDataAdvisory:
			m, err := getAdvisory(tx, advisoryContentTypes.AdvisoryID(id))
			if err != nil {
				return errors.Wrap(err, "get advisory")
			}
			if m == nil {
				return nil
			}
			root.Advisories = append(root.Advisories, dbTypes.VulnerabilityDataAdvisory{
				ID:       advisoryContentTypes.AdvisoryID(id),
				Contents: m,
			})

			var r vulnerabilityRoot
			for ds, mm := range m {
				if !slices.Contains(r.DataSources, ds) {
					r.DataSources = append(r.DataSources, ds)
				}

				for rootID := range mm {
					rr, err := getRoot(tx, rootID)
					if err != nil {
						return errors.Wrap(err, "get root")
					}
					if rr.ID == "" {
						return errors.Errorf("vulnerability -> root -> %s not found", rootID)
					}

					for _, v := range rr.Vulnerabilities {
						if !slices.Contains(r.Vulnerabilities, v) {
							r.Vulnerabilities = append(r.Vulnerabilities, v)
						}
					}

					for _, ds := range rr.DataSources {
						if !slices.Contains(r.DataSources, ds) {
							r.DataSources = append(r.DataSources, ds)
						}
					}
				}
			}

			for _, v := range r.Vulnerabilities {
				m, err := getVulnerability(tx, v)
				if err != nil {
					return errors.Wrap(err, "get vulnerability")
				}
				if m == nil {
					return errors.Errorf("vulnerability -> vulnerability -> %s not found", v)
				}
				root.Vulnerabilities = append(root.Vulnerabilities, dbTypes.VulnerabilityDataVulnerability{
					ID:       v,
					Contents: m,
				})
			}

			for item, err := range c.GetVulnerabilityDetections(dbTypes.SearchDetectionAdvisory, id) {
				if err != nil {
					return errors.Wrap(err, "get advisory detections")
				}
				root.Detections = append(root.Detections, item)
			}

			for _, datasource := range r.DataSources {
				ds, err := c.GetDataSource(sourceTypes.SourceID(datasource))
				if err != nil {
					return errors.Wrap(err, "get datasource")
				}
				root.DataSources = append(root.DataSources, *ds)
			}

			return nil
		case dbTypes.SearchDataVulnerability:
			m, err := getVulnerability(tx, vulnerabilityContentTypes.VulnerabilityID(id))
			if err != nil {
				return errors.Wrap(err, "get vulnerability")
			}
			if m == nil {
				return nil
			}
			root.Vulnerabilities = append(root.Vulnerabilities, dbTypes.VulnerabilityDataVulnerability{
				ID:       vulnerabilityContentTypes.VulnerabilityID(id),
				Contents: m,
			})

			var r vulnerabilityRoot
			for ds, mm := range m {
				if !slices.Contains(r.DataSources, ds) {
					r.DataSources = append(r.DataSources, ds)
				}

				for rootID := range mm {
					rr, err := getRoot(tx, rootID)
					if err != nil {
						return errors.Wrap(err, "get root")
					}
					if rr.ID == "" {
						return errors.Errorf("vulnerability -> root -> %s not found", rootID)
					}

					for _, a := range rr.Advisories {
						if !slices.Contains(r.Advisories, a) {
							r.Advisories = append(r.Advisories, a)
						}
					}

					for _, ds := range rr.DataSources {
						if !slices.Contains(r.DataSources, ds) {
							r.DataSources = append(r.DataSources, ds)
						}
					}
				}
			}

			for _, a := range r.Advisories {
				m, err := getAdvisory(tx, a)
				if err != nil {
					return errors.Wrap(err, "get advisory")
				}
				if m == nil {
					return errors.Errorf("vulnerability -> advisory -> %s not found", a)
				}
				root.Advisories = append(root.Advisories, dbTypes.VulnerabilityDataAdvisory{
					ID:       a,
					Contents: m,
				})
			}

			for item, err := range c.GetVulnerabilityDetections(dbTypes.SearchDetectionVulnerability, id) {
				if err != nil {
					return errors.Wrap(err, "get vulnerability detections")
				}
				root.Detections = append(root.Detections, item)
			}

			for _, datasource := range r.DataSources {
				ds, err := c.GetDataSource(sourceTypes.SourceID(datasource))
				if err != nil {
					return errors.Wrap(err, "get datasource")
				}
				root.DataSources = append(root.DataSources, *ds)
			}

			return nil
		default:
			return errors.Errorf("unexpected search type. expected: %q, actual: %s", []dbTypes.SearchDataType{dbTypes.SearchDataRoot, dbTypes.SearchDataAdvisory, dbTypes.SearchDataVulnerability}, searchType)
		}
	}); err != nil {
		return nil, errors.WithStack(err)
	}

	return &root, nil
}

func getDetection(tx *bolt.Tx, rootID dataTypes.RootID) ([]dbTypes.VulnerabilityDataDetection, error) {
	r, err := getRoot(tx, rootID)
	if err != nil {
		return nil, errors.Wrap(err, "get root")
	}

	ds := make([]dbTypes.VulnerabilityDataDetection, 0, len(r.Ecosystems))
	for _, ecosystem := range r.Ecosystems {
		eb := tx.Bucket([]byte(ecosystem))
		if eb == nil {
			return nil, errors.Errorf("bucket: %s is not exists", ecosystem)
		}

		edb := eb.Bucket([]byte("detection"))
		if edb == nil {
			return nil, errors.Errorf("bucket: %s is not exists", fmt.Sprintf("%s -> detection", ecosystem))
		}

		var m map[sourceTypes.SourceID][]conditionTypes.Condition
		if err := util.Unmarshal(edb.Get([]byte(rootID)), &m); err != nil {
			return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> detection -> %s", ecosystem, rootID))
		}

		ds = append(ds, dbTypes.VulnerabilityDataDetection{
			Ecosystem: ecosystem,
			Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{rootID: m},
		})
	}

	return ds, nil
}

func getAdvisory(tx *bolt.Tx, id advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error) {
	vb := tx.Bucket([]byte("vulnerability"))
	if vb == nil {
		return nil, errors.Errorf("bucket: %s is not exists", "vulnerability")
	}

	vab := vb.Bucket([]byte("advisory"))
	if vab == nil {
		return nil, errors.Errorf("bucket: %s is not exists", "vulnerability -> advisory")
	}

	bs := vab.Get([]byte(id))
	if len(bs) == 0 {
		return nil, nil
	}

	var m map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
	if err := util.Unmarshal(bs, &m); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability -> advisory -> %s", id))
	}

	return m, nil
}

func getVulnerability(tx *bolt.Tx, id vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error) {
	vb := tx.Bucket([]byte("vulnerability"))
	if vb == nil {
		return nil, errors.Errorf("bucket: %s is not exists", "vulnerability")
	}

	vvb := vb.Bucket([]byte("vulnerability"))
	if vvb == nil {
		return nil, errors.Errorf("bucket: %s is not exists", "vulnerability -> vulnerability")
	}

	bs := vvb.Get([]byte(id))
	if len(bs) == 0 {
		return nil, nil
	}

	var m map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
	if err := util.Unmarshal(bs, &m); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability -> vulnerability -> %s", id))
	}

	return m, nil
}

func getRoot(tx *bolt.Tx, id dataTypes.RootID) (vulnerabilityRoot, error) {
	vb := tx.Bucket([]byte("vulnerability"))
	if vb == nil {
		return vulnerabilityRoot{}, errors.Errorf("bucket: %s is not exists", "vulnerability")
	}

	vrb := vb.Bucket([]byte("root"))
	if vrb == nil {
		return vulnerabilityRoot{}, errors.Errorf("bucket: %s is not exists", "vulnerability -> root")
	}

	bs := vrb.Get([]byte(id))
	if len(bs) == 0 {
		return vulnerabilityRoot{}, nil
	}

	var r vulnerabilityRoot
	if err := util.Unmarshal(bs, &r); err != nil {
		return vulnerabilityRoot{}, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability -> root -> %s", id))
	}

	return r, nil
}

func (c *Connection) PutVulnerabilityData(root string) error {
	if err := c.conn.Update(func(tx *bolt.Tx) error {
		if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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
			defer f.Close() //nolint:errcheck

			var data dataTypes.Data
			if err := json.NewDecoder(f).Decode(&data); err != nil {
				return errors.Wrapf(err, "decode %s", path)
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
	}); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func putDetection(tx *bolt.Tx, data dataTypes.Data) error {
	for _, d := range data.Detections {
		eb, err := tx.CreateBucketIfNotExists([]byte(d.Ecosystem))
		if err != nil {
			return errors.Wrapf(err, "create bucket: %s if not exists", d.Ecosystem)
		}

		edb, err := eb.CreateBucketIfNotExists([]byte("detection"))
		if err != nil {
			return errors.Wrapf(err, "create bucket: %s if not exists", fmt.Sprintf("%s -> detection", d.Ecosystem))
		}

		m := make(map[sourceTypes.SourceID][]conditionTypes.Condition)
		if bs := edb.Get([]byte(data.ID)); len(bs) > 0 {
			if err := util.Unmarshal(bs, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> detection -> %s", d.Ecosystem, data.ID))
			}
		}
		m[data.DataSource.ID] = d.Conditions

		bs, err := util.Marshal(m)
		if err != nil {
			return errors.Wrap(err, "marshal conditions map")
		}

		if err := edb.Put([]byte(data.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("%s -> detection -> %s", d.Ecosystem, data.ID))
		}

		eib, err := eb.CreateBucketIfNotExists([]byte("index"))
		if err != nil {
			return errors.Wrapf(err, "create bucket: %s if not exists", fmt.Sprintf("%s -> index", d.Ecosystem))
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
				if err := util.Unmarshal(bs, &rootIDs); err != nil {
					return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> index -> %s", d.Ecosystem, p))
				}
			}
			if !slices.Contains(rootIDs, data.ID) {
				rootIDs = append(rootIDs, data.ID)
			}

			bs, err := util.Marshal(rootIDs)
			if err != nil {
				return errors.Wrap(err, "marshal root IDs")
			}

			if err := eib.Put([]byte(p), bs); err != nil {
				return errors.Wrapf(err, "put %s", fmt.Sprintf("%s -> index -> %s", d.Ecosystem, p))
			}
		}
	}

	return nil
}

func putAdvisory(tx *bolt.Tx, data dataTypes.Data) error {
	vb := tx.Bucket([]byte("vulnerability"))
	if vb == nil {
		return errors.Errorf("bucket: %s is not exists", "vulnerability")
	}

	vab := vb.Bucket([]byte("advisory"))
	if vab == nil {
		return errors.Errorf("bucket: %s is not exists", "vulnerability -> advisory")
	}

	for _, a := range data.Advisories {
		m := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory)
		if bs := vab.Get([]byte(a.Content.ID)); len(bs) > 0 {
			if err := util.Unmarshal(bs, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability -> advisory -> %s", a.Content.ID))
			}
		}
		if m[data.DataSource.ID] == nil {
			m[data.DataSource.ID] = make(map[dataTypes.RootID][]advisoryTypes.Advisory)
		}
		m[data.DataSource.ID][data.ID] = append(m[data.DataSource.ID][data.ID], a)

		bs, err := util.Marshal(m)
		if err != nil {
			return errors.Wrap(err, "marshal advisory map")
		}

		if err := vab.Put([]byte(a.Content.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("vulnerability -> advisory -> %s", a.Content.ID))
		}
	}

	return nil
}

func putVulnerability(tx *bolt.Tx, data dataTypes.Data) error {
	vb := tx.Bucket([]byte("vulnerability"))
	if vb == nil {
		return errors.Errorf("bucket: %s is not exists", "vulnerability")
	}

	vvb := vb.Bucket([]byte("vulnerability"))
	if vvb == nil {
		return errors.Errorf("bucket: %s is not exists", "vulnerability -> vulnerability")
	}

	for _, v := range data.Vulnerabilities {
		m := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
		if bs := vvb.Get([]byte(v.Content.ID)); len(bs) > 0 {
			if err := util.Unmarshal(bs, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability -> vulnerability -> %s", v.Content.ID))
			}
		}
		if m[data.DataSource.ID] == nil {
			m[data.DataSource.ID] = make(map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
		}
		m[data.DataSource.ID][data.ID] = append(m[data.DataSource.ID][data.ID], v)

		bs, err := util.Marshal(m)
		if err != nil {
			return errors.Wrap(err, "marshal vulnerability map")
		}

		if err := vvb.Put([]byte(v.Content.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("vulnerability -> vulnerability -> %s", v.Content.ID))
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
		return errors.Errorf("bucket: %s is not exists", "vulnerability")
	}

	vrb := vb.Bucket([]byte("root"))
	if vrb == nil {
		return errors.Errorf("bucket: %s is not exists", "vulnerability -> root")
	}

	if bs := vrb.Get([]byte(root.ID)); len(bs) > 0 {
		var r vulnerabilityRoot
		if err := util.Unmarshal(bs, &r); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability -> root -> %s", r.ID))
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

	bs, err := util.Marshal(root)
	if err != nil {
		return errors.Wrap(err, "marshal root")
	}

	if err := vrb.Put([]byte(root.ID), bs); err != nil {
		return errors.Wrapf(err, "put %s", fmt.Sprintf("vulnerability -> root -> %s", root.ID))
	}

	return nil
}

func (c *Connection) GetDataSource(id sourceTypes.SourceID) (*datasourceTypes.DataSource, error) {
	var v datasourceTypes.DataSource
	if err := c.conn.View(func(tx *bolt.Tx) error {
		sb := tx.Bucket([]byte("datasource"))
		if sb == nil {
			return errors.Errorf("bucket: %s is not exists", "datasource")
		}

		if err := util.Unmarshal(sb.Get([]byte(id)), &v); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("datasource -> %s", id))
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return &v, nil
}

func (c *Connection) PutDataSource(root string) error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		sb := tx.Bucket([]byte("datasource"))
		if sb == nil {
			return errors.Errorf("bucket: %s is not exists", "datasource")
		}

		f, err := os.Open(root)
		if err != nil {
			return errors.Wrapf(err, "open %s", root)
		}
		defer f.Close() //nolint:errcheck

		var datasource datasourceTypes.DataSource
		if err := json.NewDecoder(f).Decode(&datasource); err != nil {
			return errors.Wrapf(err, "decode %s", root)
		}

		bs, err := util.Marshal(datasource)
		if err != nil {
			return errors.Wrap(err, "marshal datasource")
		}

		if err := sb.Put([]byte(datasource.ID), bs); err != nil {
			return errors.Wrapf(err, "put %s", fmt.Sprintf("datasource -> %s", datasource.ID))
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
				return errors.Wrapf(err, "delete bucket: %s", n)
			}
		}

		return nil
	})
}

func (c *Connection) Initialize() error {
	return c.conn.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucket([]byte("metadata")); err != nil {
			return errors.Wrapf(err, "create bucket: %s", "metadata")
		}

		vb, err := tx.CreateBucket([]byte("vulnerability"))
		if err != nil {
			return errors.Wrapf(err, "create bucket: %s", "vulnerability")
		}

		if _, err := vb.CreateBucket([]byte("root")); err != nil {
			return errors.Wrapf(err, "create bucket: %s", "vulnerability -> root")
		}

		if _, err := vb.CreateBucket([]byte("advisory")); err != nil {
			return errors.Wrapf(err, "create bucket: %s", "vulnerability -> advisory")
		}

		if _, err := vb.CreateBucket([]byte("vulnerability")); err != nil {
			return errors.Wrapf(err, "create bucket: %s", "vulnerability -> vulnerability")
		}

		if _, err := tx.CreateBucket([]byte("datasource")); err != nil {
			return errors.Wrapf(err, "create bucket: %s", "datasource")
		}

		return nil
	})
}
