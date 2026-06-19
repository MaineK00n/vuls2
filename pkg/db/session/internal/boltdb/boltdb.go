package boltdb

import (
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"

	attackTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack"
	kindTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/kind"
	capecTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/util"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/MaineK00n/vuls2/pkg/version"
)

const (
	SchemaVersion = 0
)

// boltdb: metadata:db -> dbTypes.Metadata

// boltdb: vulnerability:root:<Root ID> -> vulnerabilityRoot

// boltdb: vulnerability:advisory:<Advisory ID> -> map[<Source ID>][<Root ID>][]advisoryTypes.Advisory

// boltdb: vulnerability:vulnerability:<CVE ID> -> map[<Source ID>][<Root ID>][]vulnerabilityTypes.Vulnerability

// boltdb: <ecosystem>:index:<package> -> [<Root ID>]

// boltdb: <ecosystem>:detection:<Root ID> -> map[<Source ID>][]conditionTypes.Condition

// boltdb: microsoft:kb:<KB ID> -> map[<Source ID>]microsoftkbTypes.KB

// boltdb: attack:<Kind>:<Attack ID> -> map[<Source ID>]attackTypes.Attack

// boltdb: capec:<CAPEC ID> -> map[<Source ID>]capecTypes.CAPEC

// boltdb: cwe:<CWE ID> -> map[<Source ID>]cweTypes.CWE

// boltdb: datasource:<Source ID> -> datasourceTypes.DataSource

type Config struct {
	Path         string
	PutBatchSize int

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

	db, err := bolt.Open(c.Config.Path, func() os.FileMode {
		if c.Config.Options != nil && c.Config.Options.ReadOnly {
			return 0400
		}
		return 0600
	}(), c.Config.Options)
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

		if err := util.Unmarshal(bs, &v); err != nil {
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

	bs, err := util.Marshal(metadata)
	if err != nil {
		return errors.Wrap(err, "marshal metadata")
	}

	if err := mb.Put([]byte("db"), bs); err != nil {
		return errors.Wrapf(err, "put %q", "metadata -> db")
	}

	return nil
}

const defaultPutBatchSize = 1000

// pkgIndex is the in-memory accumulation of <ecosystem>:index:<package> -> rootIDs
// built up across data batches and flushed once at the end of Put. This avoids
// the per-file read-modify-write of the on-disk index bucket, which is the
// dominant cost when Put is split across many small transactions.
type pkgIndex map[ecosystemTypes.Ecosystem]map[string]map[dataTypes.RootID]struct{}

// Put walks the extracted data directory under root and stores all files into the database.
// Writes are batched into transactions of up to Config.PutBatchSize files for memory efficiency.
// If PutBatchSize is non-positive, the default (1000) is used.
// Index entries are accumulated in memory across all data batches and flushed at the end,
// so each indexed package is read-modify-written at most once per Put.
// Atomicity across batches is not guaranteed; if an error occurs mid-way, the database may
// contain partial data and should be re-created from scratch (db init + db add).
func (c *Connection) Put(root string) error {
	batchSize := c.Config.PutBatchSize
	if batchSize <= 0 {
		batchSize = defaultPutBatchSize
	}

	idx := make(pkgIndex)

	dataPaths, err := collectJSONPaths(filepath.Join(root, "data"))
	if err != nil {
		return errors.Wrap(err, "collect data paths")
	}
	for batch := range slices.Chunk(dataPaths, batchSize) {
		if err := c.conn.Update(func(tx *bolt.Tx) error {
			for _, p := range batch {
				if err := putDataFile(tx, p, idx); err != nil {
					return errors.Wrapf(err, "put data file %s", p)
				}
			}
			return nil
		}); err != nil {
			return errors.Wrap(err, "put data batch")
		}
	}

	// Each ecosystem's index lives in its own B+tree sub-bucket, so process
	// one ecosystem at a time. Package order is map-iteration order; sorting
	// it was tested and made no measurable difference to total Put time.
	for eco, byPkg := range idx {
		for batch := range slices.Chunk(slices.Collect(maps.Keys(byPkg)), batchSize) {
			if err := c.conn.Update(func(tx *bolt.Tx) error {
				for _, pkg := range batch {
					if err := putIndexEntry(tx, eco, pkg, slices.Collect(maps.Keys(byPkg[pkg]))); err != nil {
						return errors.Wrapf(err, "put index entry %s -> %s", eco, pkg)
					}
				}
				return nil
			}); err != nil {
				return errors.Wrap(err, "put index batch")
			}
		}
	}

	kbPaths, err := collectJSONPaths(filepath.Join(root, "microsoftkb"))
	if err != nil {
		return errors.Wrap(err, "collect microsoftkb paths")
	}
	for batch := range slices.Chunk(kbPaths, batchSize) {
		if err := c.conn.Update(func(tx *bolt.Tx) error {
			for _, p := range batch {
				if err := putMicrosoftKBFile(tx, p); err != nil {
					return errors.Wrapf(err, "put microsoftkb file %s", p)
				}
			}
			return nil
		}); err != nil {
			return errors.Wrap(err, "put microsoftkb batch")
		}
	}

	for _, spec := range []struct {
		dir string
		put func(*bolt.Tx, string) error
	}{
		{dir: "attack", put: putAttackFile},
		{dir: "capec", put: putCAPECFile},
		{dir: "cwe", put: putCWEFile},
	} {
		paths, err := collectJSONPaths(filepath.Join(root, spec.dir))
		if err != nil {
			return errors.Wrapf(err, "collect %s paths", spec.dir)
		}
		for batch := range slices.Chunk(paths, batchSize) {
			if err := c.conn.Update(func(tx *bolt.Tx) error {
				for _, p := range batch {
					if err := spec.put(tx, p); err != nil {
						return errors.Wrapf(err, "put %s file %s", spec.dir, p)
					}
				}
				return nil
			}); err != nil {
				return errors.Wrapf(err, "put %s batch", spec.dir)
			}
		}
	}

	// Write datasource and metadata in a final transaction.
	// Metadata acts as a completion marker.
	if err := c.conn.Update(func(tx *bolt.Tx) error {
		if err := putDataSourceFile(tx, filepath.Join(root, "datasource.json")); err != nil {
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
		return errors.Wrap(err, "put datasource and metadata")
	}

	return nil
}

func collectJSONPaths(dir string) ([]string, error) {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "stat %s", dir)
	}

	var paths []string
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".json" {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", dir)
	}
	return paths, nil
}

func putDataFile(tx *bolt.Tx, path string, idx pkgIndex) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	var data dataTypes.Data
	if err := json.UnmarshalRead(f, &data); err != nil {
		return errors.Wrapf(err, "unmarshal %s", path)
	}

	if err := putDetection(tx, data, idx); err != nil {
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
}

func putDetection(tx *bolt.Tx, data dataTypes.Data, idx pkgIndex) error {
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
			if err := util.Unmarshal(bs, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("%s -> detection -> %s", d.Ecosystem, data.ID))
			}
		}
		m[data.DataSource.ID] = d.Conditions

		bs, err := util.Marshal(m)
		if err != nil {
			return errors.Wrap(err, "marshal conditions map")
		}

		if err := edb.Put([]byte(data.ID), bs); err != nil {
			return errors.Wrapf(err, "put %q", fmt.Sprintf("%s -> detection -> %s", d.Ecosystem, data.ID))
		}

		// Eagerly create the index sub-bucket per detection so that ecosystems
		// with detections but no packages (e.g. criteria of only `none_exist`)
		// still have an empty index bucket.
		if _, err := eb.CreateBucketIfNotExists([]byte("index")); err != nil {
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

		if _, ok := idx[d.Ecosystem]; !ok {
			idx[d.Ecosystem] = make(map[string]map[dataTypes.RootID]struct{})
		}
		for _, p := range slices.Compact(pkgs) {
			if _, ok := idx[d.Ecosystem][p]; !ok {
				idx[d.Ecosystem][p] = make(map[dataTypes.RootID]struct{})
			}
			idx[d.Ecosystem][p][data.ID] = struct{}{}
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
			if err := util.Unmarshal(bs, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> advisory -> %s", a.Content.ID))
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
			if err := util.Unmarshal(bs, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> vulnerability -> %s", v.Content.ID))
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
			return errors.Wrapf(err, "put %q", fmt.Sprintf("vulnerability -> vulnerability -> %s", v.Content.ID))
		}
	}

	return nil
}

func putMicrosoftKBFile(tx *bolt.Tx, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	var kb microsoftkbTypes.KB
	if err := json.UnmarshalRead(f, &kb); err != nil {
		return errors.Wrapf(err, "unmarshal %s", path)
	}

	if err := putMicrosoftKB(tx, kb); err != nil {
		return errors.Wrap(err, "put microsoft kb")
	}

	return nil
}

func putMicrosoftKB(tx *bolt.Tx, kb microsoftkbTypes.KB) error {
	eb, err := tx.CreateBucketIfNotExists([]byte(ecosystemTypes.EcosystemTypeMicrosoft))
	if err != nil {
		return errors.Wrapf(err, "create %q if not exists", ecosystemTypes.EcosystemTypeMicrosoft)
	}

	ekb, err := eb.CreateBucketIfNotExists([]byte("kb"))
	if err != nil {
		return errors.Wrapf(err, "create %q if not exists", fmt.Sprintf("%s -> kb", ecosystemTypes.EcosystemTypeMicrosoft))
	}

	m := make(map[sourceTypes.SourceID]microsoftkbTypes.KB)
	if bs := ekb.Get([]byte(kb.KBID)); len(bs) > 0 {
		if err := util.Unmarshal(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("%s -> kb -> %s", ecosystemTypes.EcosystemTypeMicrosoft, kb.KBID))
		}
	}
	m[kb.DataSource.ID] = kb

	bs, err := util.Marshal(m)
	if err != nil {
		return errors.Wrap(err, "marshal microsoft kb")
	}

	if err := ekb.Put([]byte(kb.KBID), bs); err != nil {
		return errors.Wrapf(err, "put %q", fmt.Sprintf("%s -> kb -> %s", ecosystemTypes.EcosystemTypeMicrosoft, kb.KBID))
	}

	return nil
}

// putIndexEntry merges the in-memory rootID set for one (ecosystem, package)
// with whatever is already on disk and writes the union back. Within a single
// Put call this happens once per package; subsequent Put calls against the
// same DB re-read and merge per call.
func putIndexEntry(tx *bolt.Tx, eco ecosystemTypes.Ecosystem, pkg string, rids []dataTypes.RootID) error {
	eb, err := tx.CreateBucketIfNotExists([]byte(eco))
	if err != nil {
		return errors.Wrapf(err, "create %q if not exists", eco)
	}
	eib, err := eb.CreateBucketIfNotExists([]byte("index"))
	if err != nil {
		return errors.Wrapf(err, "create %q if not exists", fmt.Sprintf("%s -> index", eco))
	}

	rootIDs := rids
	if bs := eib.Get([]byte(pkg)); len(bs) > 0 {
		var existing []dataTypes.RootID
		if err := util.Unmarshal(bs, &existing); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("%s -> index -> %s", eco, pkg))
		}
		rootIDs = append(rootIDs, existing...)
	}
	slices.Sort(rootIDs)
	rootIDs = slices.Compact(rootIDs)

	bs, err := util.Marshal(rootIDs)
	if err != nil {
		return errors.Wrap(err, "marshal root IDs")
	}
	if err := eib.Put([]byte(pkg), bs); err != nil {
		return errors.Wrapf(err, "put %q", fmt.Sprintf("%s -> index -> %s", eco, pkg))
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
		var r vulnerabilityRoot
		if err := util.Unmarshal(bs, &r); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> root -> %s", r.ID))
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
		return errors.Wrapf(err, "put %q", fmt.Sprintf("vulnerability -> root -> %s", root.ID))
	}

	return nil
}

func putDataSourceFile(tx *bolt.Tx, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	var datasource datasourceTypes.DataSource
	if err := json.UnmarshalRead(f, &datasource); err != nil {
		return errors.Wrapf(err, "unmarshal %s", path)
	}

	sb := tx.Bucket([]byte("datasource"))
	if sb == nil {
		return errors.Errorf("%q is not exists", "datasource")
	}

	if sb.Get([]byte(datasource.ID)) != nil {
		return errors.Errorf("%q already exists", fmt.Sprintf("datasource -> %s", datasource.ID))
	}

	bs, err := util.Marshal(datasource)
	if err != nil {
		return errors.Wrap(err, "marshal datasource")
	}

	if err := sb.Put([]byte(datasource.ID), bs); err != nil {
		return errors.Wrapf(err, "put %q", fmt.Sprintf("datasource -> %q", datasource.ID))
	}

	return nil
}

func putAttackFile(tx *bolt.Tx, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	var a attackTypes.Attack
	if err := json.UnmarshalRead(f, &a); err != nil {
		return errors.Wrapf(err, "unmarshal %s", path)
	}
	if a.ID == "" || a.Kind == "" {
		return nil
	}

	// ATT&CK's external_id namespace is per-Kind, not global: pre-2019
	// 1:1 course-of-action mitigations share T#### ids with their live
	// Techniques. A nested bucket per Kind is the canonical bolt way to
	// hold both records without one overwriting the other.
	parent, err := tx.CreateBucketIfNotExists([]byte("attack"))
	if err != nil {
		return errors.Wrapf(err, "create %q bucket", "attack")
	}
	b, err := parent.CreateBucketIfNotExists([]byte(string(a.Kind)))
	if err != nil {
		return errors.Wrapf(err, "create %q bucket", fmt.Sprintf("attack -> %s", a.Kind))
	}

	m := make(map[sourceTypes.SourceID]attackTypes.Attack)
	if bs := b.Get([]byte(a.ID)); len(bs) > 0 {
		if err := util.Unmarshal(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("attack -> %s -> %s", a.Kind, a.ID))
		}
	}
	m[a.DataSource.ID] = a

	bs, err := util.Marshal(m)
	if err != nil {
		return errors.Wrapf(err, "marshal attack %s/%s", a.Kind, a.ID)
	}

	if err := b.Put([]byte(a.ID), bs); err != nil {
		return errors.Wrapf(err, "put %q", fmt.Sprintf("attack -> %s -> %s", a.Kind, a.ID))
	}

	return nil
}

func putCAPECFile(tx *bolt.Tx, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	var c capecTypes.CAPEC
	if err := json.UnmarshalRead(f, &c); err != nil {
		return errors.Wrapf(err, "unmarshal %s", path)
	}
	if c.ID == "" {
		return nil
	}

	b, err := tx.CreateBucketIfNotExists([]byte("capec"))
	if err != nil {
		return errors.Wrapf(err, "create %q bucket", "capec")
	}

	m := make(map[sourceTypes.SourceID]capecTypes.CAPEC)
	if bs := b.Get([]byte(c.ID)); len(bs) > 0 {
		if err := util.Unmarshal(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("capec -> %s", c.ID))
		}
	}
	m[c.DataSource.ID] = c

	bs, err := util.Marshal(m)
	if err != nil {
		return errors.Wrapf(err, "marshal capec %s", c.ID)
	}

	if err := b.Put([]byte(c.ID), bs); err != nil {
		return errors.Wrapf(err, "put %q", fmt.Sprintf("capec -> %s", c.ID))
	}

	return nil
}

func putCWEFile(tx *bolt.Tx, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	var w cweTypes.CWE
	if err := json.UnmarshalRead(f, &w); err != nil {
		return errors.Wrapf(err, "unmarshal %s", path)
	}
	if w.ID == "" {
		return nil
	}

	b, err := tx.CreateBucketIfNotExists([]byte("cwe"))
	if err != nil {
		return errors.Wrapf(err, "create %q bucket", "cwe")
	}

	m := make(map[sourceTypes.SourceID]cweTypes.CWE)
	if bs := b.Get([]byte(w.ID)); len(bs) > 0 {
		if err := util.Unmarshal(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("cwe -> %s", w.ID))
		}
	}
	m[w.DataSource.ID] = w

	bs, err := util.Marshal(m)
	if err != nil {
		return errors.Wrapf(err, "marshal cwe %s", w.ID)
	}

	if err := b.Put([]byte(w.ID), bs); err != nil {
		return errors.Wrapf(err, "put %q", fmt.Sprintf("cwe -> %s", w.ID))
	}

	return nil
}

func (c *Connection) GetAttack(kind kindTypes.Kind, id string) (map[sourceTypes.SourceID]attackTypes.Attack, error) {
	var m map[sourceTypes.SourceID]attackTypes.Attack
	if err := c.conn.View(func(tx *bolt.Tx) error {
		parent := tx.Bucket([]byte("attack"))
		if parent == nil {
			return errors.Errorf("%q is not exists", "attack")
		}
		// Per-Kind sub-buckets are created lazily by putAttackFile,
		// so a missing one means "no record of this kind has been
		// loaded yet" — surface it as a regular not-found.
		b := parent.Bucket([]byte(string(kind)))
		if b == nil {
			return errors.Wrapf(dbTypes.ErrNotFoundAttack, "%q not found", fmt.Sprintf("attack -> %s -> %s", kind, id))
		}
		bs := b.Get([]byte(id))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundAttack, "%q not found", fmt.Sprintf("attack -> %s -> %s", kind, id))
		}
		if err := util.Unmarshal(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("attack -> %s -> %s", kind, id))
		}
		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
}

func (c *Connection) GetCAPEC(id string) (map[sourceTypes.SourceID]capecTypes.CAPEC, error) {
	var m map[sourceTypes.SourceID]capecTypes.CAPEC
	if err := c.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("capec"))
		if b == nil {
			return errors.Errorf("%q is not exists", "capec")
		}
		bs := b.Get([]byte(id))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundCAPEC, "%q not found", fmt.Sprintf("capec -> %s", id))
		}
		if err := util.Unmarshal(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("capec -> %s", id))
		}
		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
}

func (c *Connection) GetCWE(id string) (map[sourceTypes.SourceID]cweTypes.CWE, error) {
	var m map[sourceTypes.SourceID]cweTypes.CWE
	if err := c.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("cwe"))
		if b == nil {
			return errors.Errorf("%q is not exists", "cwe")
		}
		bs := b.Get([]byte(id))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundCWE, "%q not found", fmt.Sprintf("cwe -> %s", id))
		}
		if err := util.Unmarshal(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("cwe -> %s", id))
		}
		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
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

		var r vulnerabilityRoot
		if err := util.Unmarshal(bs, &r); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> root -> %s", id))
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

		if err := util.Unmarshal(bs, &m); err != nil {
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

		if err := util.Unmarshal(bs, &m); err != nil {
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
			case "metadata", "vulnerability", "attack", "capec", "cwe", "datasource":
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

		if err := util.Unmarshal(bs, &rootIDs); err != nil {
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

		if err := util.Unmarshal(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("%s -> detection -> %s", ecosystem, rootID))
		}

		return nil
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
}

func (c *Connection) GetMicrosoftKB(kbid string) (map[sourceTypes.SourceID]microsoftkbTypes.KB, error) {
	var m map[sourceTypes.SourceID]microsoftkbTypes.KB
	if err := c.conn.View(func(tx *bolt.Tx) error {
		eb := tx.Bucket([]byte(ecosystemTypes.EcosystemTypeMicrosoft))
		if eb == nil {
			return errors.Wrapf(dbTypes.ErrNotFoundEcosystem, "%q not found", ecosystemTypes.EcosystemTypeMicrosoft)
		}

		ekb := eb.Bucket([]byte("kb"))
		if ekb == nil {
			return errors.Errorf("%q not found", fmt.Sprintf("%s -> kb", ecosystemTypes.EcosystemTypeMicrosoft))
		}

		bs := ekb.Get([]byte(kbid))
		if len(bs) == 0 {
			return errors.Wrapf(dbTypes.ErrNotFoundMicrosoftKB, "%q not found", fmt.Sprintf("%s -> kb -> %s", ecosystemTypes.EcosystemTypeMicrosoft, kbid))
		}

		if err := util.Unmarshal(bs, &m); err != nil {
			return errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("%s -> kb -> %s", ecosystemTypes.EcosystemTypeMicrosoft, kbid))
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
			if err := util.Unmarshal(v, &d); err != nil {
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

		if err := util.Unmarshal(bs, &v); err != nil {
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

		// attack:<Kind>:<Attack ID>, capec:<CAPEC ID>, cwe:<CWE ID>
		// are first-class catalog buckets parallel to vulnerability;
		// pre-create the parents here so GetX paths get an
		// "empty-bucket" answer instead of a missing-parent surprise
		// on a freshly-initialized db. The per-Kind ATT&CK sub-buckets
		// stay lazy — putAttackFile creates them on first Put.
		if _, err := tx.CreateBucket([]byte("attack")); err != nil {
			return errors.Wrapf(err, "create %q", "attack")
		}

		if _, err := tx.CreateBucket([]byte("capec")); err != nil {
			return errors.Wrapf(err, "create %q", "capec")
		}

		if _, err := tx.CreateBucket([]byte("cwe")); err != nil {
			return errors.Wrapf(err, "create %q", "cwe")
		}

		return nil
	})
}
