package pebble

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	pebble "github.com/cockroachdb/pebble/v2"
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

const KEY_DELEM = "#"

type Config struct {
	Path string
}

type Connection struct {
	Config *Config

	conn *pebble.DB
}

func (c *Connection) Open() error {
	if c.Config == nil {
		return errors.New("connection config is not set")
	}

	db, err := pebble.Open(c.Config.Path, nil)
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
	if err := c.getValue("metadata#db", &v); err != nil {
		return nil, err
	}

	return &v, nil
}

func (c *Connection) PutMetadata(metadata dbTypes.Metadata) error {
	return c.setValue("metadata#db", metadata)
}

func (c *Connection) getValue(key string, ref any) error {
	bs, closer, err := c.conn.Get([]byte(key))
	if err != nil {
		return errors.Wrapf(err, "get %s", key)
	}
	if err := util.Unmarshal(bs, ref); err != nil {
		return errors.Wrapf(err, "unmarshal %s", key)
	}
	if err := closer.Close(); err != nil {
		return errors.Wrapf(err, "closer for %s", key)
	}

	return nil
}

func (c *Connection) setValue(key string, value any) error {
	bs, err := util.Marshal(value)
	if err != nil {
		return errors.Wrapf(err, "marshal %s", key)
	}

	if err := c.conn.Set([]byte(key), bs, pebble.NoSync); err != nil {
		return errors.Wrapf(err, "set %s", key)
	}

	return nil
}

func (c *Connection) GetVulnerabilityDetections(done <-chan struct{}, searchType dbTypes.SearchDetectionType, queries ...string) (<-chan dbTypes.VulnerabilityDataDetection, <-chan error) {
	resCh := make(chan dbTypes.VulnerabilityDataDetection, 1)
	errCh := make(chan error, 1)

	defer close(resCh)
	defer close(errCh)

	return resCh, errCh
}

func (c *Connection) GetVulnerabilityData(searchType dbTypes.SearchDataType, id string) (*dbTypes.VulnerabilityData, error) {
	root := dbTypes.VulnerabilityData{ID: id}

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
		defer f.Close()

		var data dataTypes.Data
		if err := json.NewDecoder(f).Decode(&data); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		if err := c.putDetection(data); err != nil {
			return errors.Wrap(err, "put detection")
		}

		if err := c.putAdvisory(data); err != nil {
			return errors.Wrap(err, "put advisory")
		}

		if err := c.putVulnerability(data); err != nil {
			return errors.Wrap(err, "put vulnerability")
		}

		if err := c.putRoot(data); err != nil {
			return errors.Wrap(err, "put root")
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", root)
	}

	if err := c.conn.Compact([]byte{}, []byte{255}, true); err != nil {
		return errors.Wrapf(err, "compact")
	}

	return nil
}

func (c *Connection) putDetection(data dataTypes.Data) error {
	for _, d := range data.Detections {
		detectionKey := strings.Join([]string{string(d.Ecosystem), "detection", string(data.ID)}, KEY_DELEM)

		m := make(map[sourceTypes.SourceID][]conditionTypes.Condition)
		if err := c.getValue(detectionKey, &m); err != nil && !errors.Is(err, pebble.ErrNotFound) {
			return err
		}
		m[data.DataSource.ID] = d.Conditions
		c.setValue(detectionKey, m)

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
			indexKey := strings.Join([]string{string(d.Ecosystem), "index", p}, KEY_DELEM)

			if err := c.getValue(indexKey, &rootIDs); err != nil && !errors.Is(err, pebble.ErrNotFound) {
				return err
			}
			if slices.Contains(rootIDs, data.ID) {
				continue
			}

			rootIDs = append(rootIDs, data.ID)
			if err := c.setValue(indexKey, rootIDs); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *Connection) putAdvisory(data dataTypes.Data) error {
	for _, a := range data.Advisories {
		key := strings.Join([]string{"vulnerability", "advisory", string(a.Content.ID)}, KEY_DELEM)
		m := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory)
		if err := c.getValue(key, &m); err != nil && !errors.Is(err, pebble.ErrNotFound) {
			return err
		}
		if m[data.DataSource.ID] == nil {
			m[data.DataSource.ID] = make(map[dataTypes.RootID][]advisoryTypes.Advisory)
		}
		m[data.DataSource.ID][data.ID] = append(m[data.DataSource.ID][data.ID], a)

		if err := c.setValue(key, m); err != nil {
			return err
		}
	}

	return nil
}

func (c *Connection) putVulnerability(data dataTypes.Data) error {

	for _, v := range data.Vulnerabilities {
		key := strings.Join([]string{"vulnerability", "vulnerability", string(v.Content.ID)}, KEY_DELEM)
		m := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)

		if err := c.getValue(key, &m); err != nil && !errors.Is(err, pebble.ErrNotFound) {
			return err
		}
		if m[data.DataSource.ID] == nil {
			m[data.DataSource.ID] = make(map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
		}
		m[data.DataSource.ID][data.ID] = append(m[data.DataSource.ID][data.ID], v)

		if err := c.setValue(key, m); err != nil {
			return err
		}
	}

	return nil
}

func (c *Connection) putRoot(data dataTypes.Data) error {
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

	key := strings.Join([]string{"vulnerability", "root", string(root.ID)}, KEY_DELEM)

	var prev vulnerabilityRoot
	if err := c.getValue(key, &prev); err != nil && !errors.Is(err, pebble.ErrNotFound) {
		return err
	}

	for _, a := range prev.Advisories {
		if !slices.Contains(root.Advisories, a) {
			root.Advisories = append(root.Advisories, a)
		}
	}
	for _, v := range prev.Vulnerabilities {
		if !slices.Contains(root.Vulnerabilities, v) {
			root.Vulnerabilities = append(root.Vulnerabilities, v)
		}
	}
	for _, e := range prev.Ecosystems {
		if !slices.Contains(root.Ecosystems, e) {
			root.Ecosystems = append(root.Ecosystems, e)
		}
	}
	for _, d := range prev.DataSources {
		if !slices.Contains(root.DataSources, d) {
			root.DataSources = append(root.DataSources, d)
		}
	}

	if err := c.setValue(key, root); err != nil {
		return err
	}

	return nil
}

func (c *Connection) GetDataSource(id sourceTypes.SourceID) (*datasourceTypes.DataSource, error) {
	var v datasourceTypes.DataSource
	return &v, nil
}

func (c *Connection) PutDataSource(root string) error {
	return nil
}

func (c *Connection) DeleteAll() error {
	return nil
}

func (c *Connection) Initialize() error {
	return nil
}
