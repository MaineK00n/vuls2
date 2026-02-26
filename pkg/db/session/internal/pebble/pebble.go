package pebble

import (
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"

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
	SchemaVersion = 0
)

// Key format uses "\x00" as separator:
// metadata\x00db -> dbTypes.Metadata
// vulnerability\x00root\x00<Root ID> -> vulnerabilityRoot
// vulnerability\x00advisory\x00<Advisory ID> -> map[<Source ID>][<Root ID>][]advisoryTypes.Advisory
// vulnerability\x00vulnerability\x00<CVE ID> -> map[<Source ID>][<Root ID>][]vulnerabilityTypes.Vulnerability
// <ecosystem>\x00index\x00<package> -> [<Root ID>]
// <ecosystem>\x00detection\x00<Root ID> -> map[<Source ID>][]conditionTypes.Condition
// datasource\x00<Source ID> -> datasourceTypes.DataSource

const sep = "\x00"

type Config struct {
	Path string

	Options *pebble.Options
}

type Connection struct {
	Config *Config

	conn *pebble.DB
}

func (c *Connection) Open() error {
	if c.Config == nil {
		return errors.New("connection config is not set")
	}

	opts := c.Config.Options
	if opts == nil {
		opts = &pebble.Options{}
	} else {
		opts = opts.Clone()
	}
	opts.Merger = VulsMerger

	db, err := pebble.Open(c.Config.Path, opts)
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

func makeKey(parts ...string) []byte {
	return []byte(strings.Join(parts, sep))
}

func (c *Connection) GetMetadata() (*dbTypes.Metadata, error) {
	bs, closer, err := c.conn.Get(makeKey("metadata", "db"))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, errors.Wrapf(dbTypes.ErrNotFoundMetadata, "%q not found", "metadata -> db")
		}
		return nil, errors.WithStack(err)
	}
	defer closer.Close()

	var v dbTypes.Metadata
	if err := util.Unmarshal(bs, &v); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %q", "metadata -> db")
	}

	return &v, nil
}

func (c *Connection) PutMetadata(metadata dbTypes.Metadata) error {
	bs, err := util.Marshal(metadata)
	if err != nil {
		return errors.Wrap(err, "marshal metadata")
	}

	if err := c.conn.Set(makeKey("metadata", "db"), bs, pebble.Sync); err != nil {
		return errors.Wrapf(err, "put %q", "metadata -> db")
	}

	return nil
}

// maxBatchSize is the threshold at which a batch is committed and a new one is
// created to limit WAL file size and memory usage.
const maxBatchSize = 256 << 20 // 256MB

func (c *Connection) Put(root string) error {
	batch := c.conn.NewBatch()

	commitIfNeeded := func() error {
		if batch.Len() < maxBatchSize {
			return nil
		}
		if err := batch.Commit(pebble.NoSync); err != nil {
			return errors.Wrap(err, "commit batch")
		}
		if err := batch.Close(); err != nil {
			return errors.Wrap(err, "close batch")
		}
		batch = c.conn.NewBatch()
		return nil
	}

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

		if err := putDetection(batch, data); err != nil {
			return errors.Wrap(err, "put detection")
		}

		if err := putAdvisory(batch, data); err != nil {
			return errors.Wrap(err, "put advisory")
		}

		if err := putVulnerability(batch, data); err != nil {
			return errors.Wrap(err, "put vulnerability")
		}

		if err := putRoot(batch, data); err != nil {
			return errors.Wrap(err, "put root")
		}

		if err := commitIfNeeded(); err != nil {
			return err
		}

		return nil
	}); err != nil {
		batch.Close()
		return errors.Wrapf(err, "walk %s", root)
	}

	f, err := os.Open(filepath.Join(root, "datasource.json"))
	if err != nil {
		batch.Close()
		return errors.Wrapf(err, "open %s", filepath.Join(root, "datasource.json"))
	}
	defer f.Close()

	var ds datasourceTypes.DataSource
	if err := json.UnmarshalRead(f, &ds); err != nil {
		batch.Close()
		return errors.Wrapf(err, "unmarshal %s", filepath.Join(root, "datasource.json"))
	}

	bs, err := util.Marshal(ds)
	if err != nil {
		batch.Close()
		return errors.Wrap(err, "marshal datasource")
	}
	if err := batch.Set(makeKey("datasource", string(ds.ID)), bs, nil); err != nil {
		batch.Close()
		return errors.Wrap(err, "put datasource")
	}

	metaBS, err := util.Marshal(dbTypes.Metadata{
		SchemaVersion: SchemaVersion,
		CreatedBy:     version.String(),
		LastModified:  time.Now().UTC(),
	})
	if err != nil {
		batch.Close()
		return errors.Wrap(err, "marshal metadata")
	}

	if err := batch.Set(makeKey("metadata", "db"), metaBS, nil); err != nil {
		batch.Close()
		return errors.Wrap(err, "put metadata")
	}

	if err := batch.Commit(pebble.Sync); err != nil {
		batch.Close()
		return errors.Wrap(err, "commit batch")
	}
	if err := batch.Close(); err != nil {
		return errors.Wrap(err, "close batch")
	}

	// Compact all data to resolve pending merge operands.
	slog.Info("Compacting database")
	if err := c.conn.Compact([]byte("\x00"), []byte("\xff"), true); err != nil {
		return errors.Wrap(err, "compact")
	}

	return nil
}

// putDetection writes detection data using Merge.
func putDetection(batch *pebble.Batch, data dataTypes.Data) error {
	for _, d := range data.Detections {
		detectionKey := makeKey(string(d.Ecosystem), "detection", string(data.ID))

		// Marshal a partial map with just this source's conditions.
		m := map[sourceTypes.SourceID][]conditionTypes.Condition{
			data.DataSource.ID: d.Conditions,
		}
		bs, err := util.Marshal(m)
		if err != nil {
			return errors.Wrap(err, "marshal detection")
		}
		if err := batch.Merge(detectionKey, bs, nil); err != nil {
			return errors.Wrapf(err, "merge %q", fmt.Sprintf("%s -> detection -> %s", d.Ecosystem, data.ID))
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
			indexKey := makeKey(string(d.Ecosystem), "index", p)

			// Marshal a single-element slice; merger will deduplicate.
			idBS, err := util.Marshal([]dataTypes.RootID{data.ID})
			if err != nil {
				return errors.Wrap(err, "marshal root ID")
			}
			if err := batch.Merge(indexKey, idBS, nil); err != nil {
				return errors.Wrapf(err, "merge %q", fmt.Sprintf("%s -> index -> %s", d.Ecosystem, p))
			}
		}
	}

	return nil
}

// putAdvisory writes advisory data using Merge.
func putAdvisory(batch *pebble.Batch, data dataTypes.Data) error {
	for _, a := range data.Advisories {
		key := makeKey("vulnerability", "advisory", string(a.Content.ID))

		// Marshal a partial map with just this source/root/advisory.
		m := map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
			data.DataSource.ID: {
				data.ID: {a},
			},
		}
		bs, err := util.Marshal(m)
		if err != nil {
			return errors.Wrap(err, "marshal advisory")
		}
		if err := batch.Merge(key, bs, nil); err != nil {
			return errors.Wrapf(err, "merge %q", fmt.Sprintf("vulnerability -> advisory -> %s", a.Content.ID))
		}
	}

	return nil
}

// putVulnerability writes vulnerability data using Merge.
func putVulnerability(batch *pebble.Batch, data dataTypes.Data) error {
	for _, v := range data.Vulnerabilities {
		key := makeKey("vulnerability", "vulnerability", string(v.Content.ID))

		// Marshal a partial map with just this source/root/vulnerability.
		m := map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
			data.DataSource.ID: {
				data.ID: {v},
			},
		}
		bs, err := util.Marshal(m)
		if err != nil {
			return errors.Wrap(err, "marshal vulnerability")
		}
		if err := batch.Merge(key, bs, nil); err != nil {
			return errors.Wrapf(err, "merge %q", fmt.Sprintf("vulnerability -> vulnerability -> %s", v.Content.ID))
		}
	}

	return nil
}

// putRoot writes root data using Merge.
func putRoot(batch *pebble.Batch, data dataTypes.Data) error {
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

	key := makeKey("vulnerability", "root", string(root.ID))
	bs, err := util.Marshal(root)
	if err != nil {
		return errors.Wrap(err, "marshal root")
	}
	if err := batch.Merge(key, bs, nil); err != nil {
		return errors.Wrapf(err, "merge %q", fmt.Sprintf("vulnerability -> root -> %s", root.ID))
	}

	return nil
}

func (c *Connection) GetRoot(id dataTypes.RootID) (dbTypes.VulnerabilityData, error) {
	key := makeKey("vulnerability", "root", string(id))

	bs, closer, err := c.conn.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return dbTypes.VulnerabilityData{}, errors.Wrapf(dbTypes.ErrNotFoundRoot, "%q not found", fmt.Sprintf("vulnerability -> root -> %s", id))
		}
		return dbTypes.VulnerabilityData{}, errors.WithStack(err)
	}
	defer closer.Close()

	var r vulnerabilityRoot
	if err := util.Unmarshal(bs, &r); err != nil {
		return dbTypes.VulnerabilityData{}, errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> root -> %s", id))
	}

	d := dbTypes.VulnerabilityData{
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

	return d, nil
}

func (c *Connection) GetAdvisory(id advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error) {
	key := makeKey("vulnerability", "advisory", string(id))

	bs, closer, err := c.conn.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, errors.Wrapf(dbTypes.ErrNotFoundAdvisory, "%q not found", fmt.Sprintf("vulnerability -> advisory -> %s", id))
		}
		return nil, errors.WithStack(err)
	}
	defer closer.Close()

	var m map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
	if err := util.Unmarshal(bs, &m); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> advisory -> %s", id))
	}

	return m, nil
}

func (c *Connection) GetVulnerability(id vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error) {
	key := makeKey("vulnerability", "vulnerability", string(id))

	bs, closer, err := c.conn.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, errors.Wrapf(dbTypes.ErrNotFoundVulnerability, "%q not found", fmt.Sprintf("vulnerability -> vulnerability -> %s", id))
		}
		return nil, errors.WithStack(err)
	}
	defer closer.Close()

	var m map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
	if err := util.Unmarshal(bs, &m); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("vulnerability -> vulnerability -> %s", id))
	}

	return m, nil
}

func (c *Connection) GetEcosystems() ([]ecosystemTypes.Ecosystem, error) {
	seen := make(map[string]struct{})
	var es []ecosystemTypes.Ecosystem

	iter, err := c.conn.NewIter(nil)
	if err != nil {
		return nil, errors.Wrap(err, "new iterator")
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		key := string(iter.Key())
		parts := strings.SplitN(key, sep, 2)
		prefix := parts[0]

		switch prefix {
		case "metadata", "vulnerability", "datasource":
		default:
			if _, ok := seen[prefix]; !ok {
				seen[prefix] = struct{}{}
				es = append(es, ecosystemTypes.Ecosystem(prefix))
			}
		}
	}

	if err := iter.Error(); err != nil {
		return nil, errors.Wrap(err, "iterator error")
	}

	return es, nil
}

func (c *Connection) GetIndex(ecosystem ecosystemTypes.Ecosystem, query string) ([]dataTypes.RootID, error) {
	key := makeKey(string(ecosystem), "index", query)

	bs, closer, err := c.conn.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			// Check if ecosystem exists at all
			prefix := []byte(string(ecosystem) + sep)
			iter, iterErr := c.conn.NewIter(&pebble.IterOptions{
				LowerBound: prefix,
				UpperBound: prefixUpperBound(prefix),
			})
			if iterErr != nil {
				return nil, errors.WithStack(iterErr)
			}
			defer iter.Close()

			if !iter.First() {
				return nil, errors.Wrapf(dbTypes.ErrNotFoundEcosystem, "%q not found", ecosystem)
			}
			return nil, errors.Wrapf(dbTypes.ErrNotFoundIndex, "%q not found", fmt.Sprintf("%s -> index -> %s", ecosystem, query))
		}
		return nil, errors.WithStack(err)
	}
	defer closer.Close()

	var rootIDs []dataTypes.RootID
	if err := util.Unmarshal(bs, &rootIDs); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("%s -> index -> %s", ecosystem, query))
	}

	return rootIDs, nil
}

func (c *Connection) GetDetection(ecosystem ecosystemTypes.Ecosystem, rootID dataTypes.RootID) (map[sourceTypes.SourceID][]conditionTypes.Condition, error) {
	key := makeKey(string(ecosystem), "detection", string(rootID))

	bs, closer, err := c.conn.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			// Check if ecosystem exists at all
			prefix := []byte(string(ecosystem) + sep)
			iter, iterErr := c.conn.NewIter(&pebble.IterOptions{
				LowerBound: prefix,
				UpperBound: prefixUpperBound(prefix),
			})
			if iterErr != nil {
				return nil, errors.WithStack(iterErr)
			}
			defer iter.Close()

			if !iter.First() {
				return nil, errors.Wrapf(dbTypes.ErrNotFoundEcosystem, "%q not found", ecosystem)
			}
			return nil, errors.Wrapf(dbTypes.ErrNotFoundDetection, "%q not found", fmt.Sprintf("%s -> detection -> %s", ecosystem, rootID))
		}
		return nil, errors.WithStack(err)
	}
	defer closer.Close()

	var m map[sourceTypes.SourceID][]conditionTypes.Condition
	if err := util.Unmarshal(bs, &m); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("%s -> detection -> %s", ecosystem, rootID))
	}

	return m, nil
}

func (c *Connection) GetDataSources() ([]datasourceTypes.DataSource, error) {
	prefix := []byte("datasource" + sep)
	iter, err := c.conn.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: prefixUpperBound(prefix),
	})
	if err != nil {
		return nil, errors.Wrap(err, "new iterator")
	}
	defer iter.Close()

	var ds []datasourceTypes.DataSource
	for iter.First(); iter.Valid(); iter.Next() {
		val, err := iter.ValueAndErr()
		if err != nil {
			return nil, errors.WithStack(err)
		}

		var d datasourceTypes.DataSource
		if err := util.Unmarshal(val, &d); err != nil {
			return nil, errors.Wrapf(err, "unmarshal %q", string(iter.Key()))
		}
		ds = append(ds, d)
	}

	if err := iter.Error(); err != nil {
		return nil, errors.Wrap(err, "iterator error")
	}

	return ds, nil
}

func (c *Connection) GetDataSource(id sourceTypes.SourceID) (datasourceTypes.DataSource, error) {
	key := makeKey("datasource", string(id))

	bs, closer, err := c.conn.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return datasourceTypes.DataSource{}, errors.Wrapf(dbTypes.ErrNotFoundDataSource, "%q not found", fmt.Sprintf("datasource -> %s", id))
		}
		return datasourceTypes.DataSource{}, errors.WithStack(err)
	}
	defer closer.Close()

	var v datasourceTypes.DataSource
	if err := util.Unmarshal(bs, &v); err != nil {
		return datasourceTypes.DataSource{}, errors.Wrapf(err, "unmarshal %q", fmt.Sprintf("datasource -> %s", id))
	}

	return v, nil
}

func (c *Connection) DeleteAll() error {
	iter, err := c.conn.NewIter(nil)
	if err != nil {
		return errors.Wrap(err, "new iterator")
	}
	defer iter.Close()

	batch := c.conn.NewBatch()
	defer batch.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		if err := batch.Delete(iter.Key(), nil); err != nil {
			return errors.Wrapf(err, "delete %q", iter.Key())
		}
	}

	if err := iter.Error(); err != nil {
		return errors.Wrap(err, "iterator error")
	}

	if err := batch.Commit(pebble.Sync); err != nil {
		return errors.Wrap(err, "commit batch")
	}

	return nil
}

func (c *Connection) Initialize() error {
	// Pebble doesn't need bucket initialization like boltdb.
	// Keys are created on demand.
	return nil
}

// prefixUpperBound returns the upper bound for prefix iteration.
// It increments the last byte of the prefix.
func prefixUpperBound(prefix []byte) []byte {
	upper := make([]byte, len(prefix))
	copy(upper, prefix)
	for i := len(upper) - 1; i >= 0; i-- {
		upper[i]++
		if upper[i] != 0 {
			return upper
		}
	}
	return nil
}
