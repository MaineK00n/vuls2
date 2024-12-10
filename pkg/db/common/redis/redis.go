package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pkg/errors"
	"github.com/redis/rueidis"

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

// redis: HASH KEY: "metadata" FIELD: "db" VALUE: dbtypes.Metadata

// redis: STRING KEY: "vulnerability#root#<Root ID>" VALUE: vulnerabilityRoot

// redis: HASH KEY: "vulnerability#advisory#<Advisory ID>" FIELD: "<Source ID>#<Root ID>" VALUE: []advisoryTypes.Advisory

// redis: HASH KEY: "vulnerability#vulnerability#<CVE ID>" FIELD: "<Source ID>#<Root ID>" VALUE: []vulnerabilityTypes.Vulnerability

// redis: SET KEY: "<ecosystem>#index#<package>" MEMBER: <Root ID>

// redis: HASH KEY: "<ecosystem>#detection#<Root ID>" FIELD: <Source ID> VALUE: []conditionTypes.Condition

// redis: HASH KEY "datasource" FIELD: <Source ID> VALUE: datasourceTypes.DataSource

type Connection struct {
	Config *rueidis.ClientOption

	conn rueidis.Client
}

func (c *Connection) Open() error {
	if c.Config == nil {
		return errors.New("connection config is not set")
	}

	client, err := rueidis.NewClient(*c.Config)
	if err != nil {
		return errors.WithStack(err)
	}
	c.conn = client
	return nil
}

func (c *Connection) Close() error {
	if c.conn == nil {
		return nil
	}
	c.conn.Close()
	return nil
}

func (c *Connection) GetMetadata() (*dbTypes.Metadata, error) {
	bs, err := c.conn.Do(context.TODO(), c.conn.B().Hget().Key("metadata").Field("db").Build()).AsBytes()
	if err != nil {
		return nil, errors.Wrapf(err, "HGET %s %s", "metadata", "db")
	}

	var v dbTypes.Metadata
	if err := util.Unmarshal(bs, &v); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %s", "metadata -> db")
	}

	return &v, nil
}

func (c *Connection) PutMetadata(metadata dbTypes.Metadata) error {
	bs, err := util.Marshal(metadata)
	if err != nil {
		return errors.Wrap(err, "marshal metadata")
	}

	if err := c.conn.Do(context.TODO(), c.conn.B().Hset().Key("metadata").FieldValue().FieldValue("db", string(bs)).Build()).Error(); err != nil {
		return errors.Wrapf(err, "HSET %s %s %q", "metadata", "db", string(bs))
	}

	return nil
}

func (c *Connection) GetVulnerabilityDetections(done <-chan struct{}, searchType dbTypes.SearchDetectionType, queries ...string) (<-chan dbTypes.VulnerabilityDataDetection, <-chan error) {
	ctx := context.TODO()

	resCh := make(chan dbTypes.VulnerabilityDataDetection, 1)
	errCh := make(chan error, 1)

	go func() {
		defer close(resCh)
		defer close(errCh)

		if err := func() error {
			switch searchType {
			case dbTypes.SearchDetectionPkg:
				if len(queries) != 2 {
					return errors.Errorf("unexpected pkg search queries. expected: %q, actual: %q", []string{"<ecosystem>", "<key>"}, queries)
				}

				rootIDs, err := c.conn.Do(ctx, c.conn.B().Smembers().Key(fmt.Sprintf("%s#index#%s", queries[0], queries[1])).Build()).AsStrSlice()
				if err != nil {
					return errors.Wrapf(err, "SMEMBERS %s", fmt.Sprintf("%s#index#%s", queries[0], queries[1]))
				}

				for _, rootID := range rootIDs {
					m, err := c.conn.Do(ctx, c.conn.B().Hgetall().Key(fmt.Sprintf("%s#detection#%s", queries[0], rootID)).Build()).AsMap()
					if err != nil {
						return errors.Wrapf(err, "HGETALL %s", fmt.Sprintf("%s#detection#%s", queries[0], rootID))
					}

					sm := make(map[sourceTypes.SourceID][]conditionTypes.Condition)
					for k, v := range m {
						bs, err := v.AsBytes()
						if err != nil {
							return errors.Wrapf(err, "as bytes %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("%s#detection#%s", queries[0], rootID), k))
						}

						var conds []conditionTypes.Condition
						if err := util.Unmarshal(bs, &conds); err != nil {
							return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("%s#detection#%s", queries[0], rootID), k))
						}
						sm[sourceTypes.SourceID(k)] = conds
					}

					select {
					case <-done:
						return nil
					case resCh <- dbTypes.VulnerabilityDataDetection{
						Ecosystem: ecosystemTypes.Ecosystem(queries[0]),
						Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{dataTypes.RootID(rootID): sm},
					}:
					}
				}

				return nil
			case dbTypes.SearchDetectionRoot:
				if len(queries) != 1 {
					return errors.Errorf("unexpected root search queries. expected: %q, actual: %q", []string{"<root id>"}, queries)
				}
				ds, err := c.getDetection(ctx, dataTypes.RootID(queries[0]))
				if err != nil {
					return errors.WithStack(err)
				}
				for _, d := range ds {
					select {
					case <-done:
						return nil
					case resCh <- d:
					}
				}

				return nil
			case dbTypes.SearchDetectionAdvisory:
				if len(queries) != 1 {
					return errors.Errorf("unexpected advisory search queries. expected: %q, actual: %q", []string{"<advisory id>"}, queries)
				}

				am, err := c.getAdvisory(ctx, advisoryContentTypes.AdvisoryID(queries[0]))
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
					ds, err := c.getDetection(ctx, rootID)
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
					select {
					case <-done:
						return nil
					case resCh <- dbTypes.VulnerabilityDataDetection{
						Ecosystem: ecosystem,
						Contents:  m,
					}:
					}
				}

				return nil
			case dbTypes.SearchDetectionVulnerability:
				if len(queries) != 1 {
					return errors.Errorf("unexpected vulnerability search queries. expected: %q, actual: %q", []string{"<vulnerability id>"}, queries)
				}

				vm, err := c.getVulnerability(ctx, vulnerabilityContentTypes.VulnerabilityID(queries[0]))
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
					ds, err := c.getDetection(ctx, rootID)
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
					select {
					case <-done:
						return nil
					case resCh <- dbTypes.VulnerabilityDataDetection{
						Ecosystem: ecosystem,
						Contents:  m,
					}:
					}
				}

				return nil
			default:
				return errors.Errorf("unexpected search type. expected: %q, actual: %s", []dbTypes.SearchDetectionType{dbTypes.SearchDetectionPkg, dbTypes.SearchDetectionRoot, dbTypes.SearchDetectionAdvisory, dbTypes.SearchDetectionVulnerability}, searchType)
			}
		}(); err != nil {
			select {
			case <-done:
				return
			case errCh <- errors.WithStack(err):
				return
			}
		}
	}()

	return resCh, errCh
}

func (c *Connection) GetVulnerabilityData(searchType dbTypes.SearchDataType, id string) (*dbTypes.VulnerabilityData, error) {
	ctx := context.TODO()

	switch searchType {
	case dbTypes.SearchDataRoot:
		root := dbTypes.VulnerabilityData{ID: id}

		r, err := c.getRoot(ctx, dataTypes.RootID(id))
		if err != nil {
			return nil, errors.Wrap(err, "get root")
		}
		if r.ID == "" {
			return &root, nil
		}

		for _, a := range r.Advisories {
			m, err := c.getAdvisory(ctx, a)
			if err != nil {
				return nil, errors.Wrap(err, "get advisory")
			}
			if m == nil {
				return nil, errors.Errorf("vulnerability#advisory#%s not found", a)
			}
			root.Advisories = append(root.Advisories, dbTypes.VulnerabilityDataAdvisory{
				ID:       a,
				Contents: m,
			})
		}

		for _, v := range r.Vulnerabilities {
			m, err := c.getVulnerability(ctx, v)
			if err != nil {
				return nil, errors.Wrap(err, "get vulnerability")
			}
			if m == nil {
				return nil, errors.Errorf("vulnerability#vulnerability#%s not found", v)
			}
			root.Vulnerabilities = append(root.Vulnerabilities, dbTypes.VulnerabilityDataVulnerability{
				ID:       v,
				Contents: m,
			})
		}

		ds, err := c.getDetection(ctx, dataTypes.RootID(id))
		if err != nil {
			return nil, errors.Wrap(err, "get detection")
		}
		root.Detections = ds

		for _, datasource := range r.DataSources {
			ds, err := c.GetDataSource(sourceTypes.SourceID(datasource))
			if err != nil {
				return nil, errors.Wrap(err, "get datasource")
			}
			root.DataSources = append(root.DataSources, *ds)
		}

		return &root, nil
	case dbTypes.SearchDataAdvisory:
		root := dbTypes.VulnerabilityData{ID: id}

		m, err := c.getAdvisory(ctx, advisoryContentTypes.AdvisoryID(id))
		if err != nil {
			return nil, errors.Wrap(err, "get advisory")
		}
		if m == nil {
			return &root, nil
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
				rr, err := c.getRoot(ctx, rootID)
				if err != nil {
					return nil, errors.Wrap(err, "get root")
				}
				if rr.ID == "" {
					return nil, errors.Errorf("vulnerability#root#%s not found", rootID)
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
			m, err := c.getVulnerability(ctx, v)
			if err != nil {
				return nil, errors.Wrap(err, "get vulnerability")
			}
			if m == nil {
				return nil, errors.Errorf("vulnerability#vulnerability#%s not found", v)
			}
			root.Vulnerabilities = append(root.Vulnerabilities, dbTypes.VulnerabilityDataVulnerability{
				ID:       v,
				Contents: m,
			})
		}

		if err := func() error {
			done := make(chan struct{})
			defer close(done)
			resCh, errCh := c.GetVulnerabilityDetections(done, dbTypes.SearchDetectionAdvisory, id)
			for {
				select {
				case item, ok := <-resCh:
					if !ok {
						return nil
					}
					root.Detections = append(root.Detections, item)
				case err, ok := <-errCh:
					if ok {
						return errors.Wrap(err, "get advisory detections")
					}
				}
			}
		}(); err != nil {
			return nil, errors.Wrap(err, "get detection")
		}

		for _, datasource := range r.DataSources {
			ds, err := c.GetDataSource(sourceTypes.SourceID(datasource))
			if err != nil {
				return nil, errors.Wrap(err, "get datasource")
			}
			root.DataSources = append(root.DataSources, *ds)
		}

		return &root, nil
	case dbTypes.SearchDataVulnerability:
		root := dbTypes.VulnerabilityData{ID: id}

		m, err := c.getVulnerability(ctx, vulnerabilityContentTypes.VulnerabilityID(id))
		if err != nil {
			return nil, errors.Wrap(err, "get vulnerability")
		}
		if m == nil {
			return &root, nil
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
				rr, err := c.getRoot(ctx, rootID)
				if err != nil {
					return nil, errors.Wrap(err, "get root")
				}
				if rr.ID == "" {
					return nil, errors.Errorf("vulnerability#root#%s not found", rootID)
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
			m, err := c.getAdvisory(ctx, a)
			if err != nil {
				return nil, errors.Wrap(err, "get advisory")
			}
			if m == nil {
				return nil, errors.Errorf("vulnerability#advisory#%s not found", a)
			}
			root.Advisories = append(root.Advisories, dbTypes.VulnerabilityDataAdvisory{
				ID:       a,
				Contents: m,
			})
		}

		if err := func() error {
			done := make(chan struct{})
			defer close(done)
			resCh, errCh := c.GetVulnerabilityDetections(done, dbTypes.SearchDetectionVulnerability, id)
			for {
				select {
				case item, ok := <-resCh:
					if !ok {
						return nil
					}
					root.Detections = append(root.Detections, item)
				case err, ok := <-errCh:
					if ok {
						return errors.Wrap(err, "get vulnerability detections")
					}
				}
			}
		}(); err != nil {
			return nil, errors.Wrap(err, "get detection")
		}

		for _, datasource := range r.DataSources {
			ds, err := c.GetDataSource(sourceTypes.SourceID(datasource))
			if err != nil {
				return nil, errors.Wrap(err, "get datasource")
			}
			root.DataSources = append(root.DataSources, *ds)
		}

		return &root, nil
	default:
		return nil, errors.Errorf("unexpected search type. expected: %q, actual: %s", []dbTypes.SearchDataType{dbTypes.SearchDataRoot, dbTypes.SearchDataAdvisory, dbTypes.SearchDataVulnerability}, searchType)
	}
}

func (c *Connection) getDetection(ctx context.Context, rootID dataTypes.RootID) ([]dbTypes.VulnerabilityDataDetection, error) {
	r, err := c.getRoot(ctx, rootID)
	if err != nil {
		return nil, errors.Wrap(err, "get root")
	}

	ds := make([]dbTypes.VulnerabilityDataDetection, 0, len(r.Ecosystems))
	for _, ecosystem := range r.Ecosystems {
		m, err := c.conn.Do(ctx, c.conn.B().Hgetall().Key(fmt.Sprintf("%s#detection#%s", ecosystem, rootID)).Build()).AsMap()
		if err != nil {
			return nil, errors.Wrapf(err, "HGETALL %s", fmt.Sprintf("%s#detection#%s", ecosystem, rootID))
		}

		cm := make(map[sourceTypes.SourceID][]conditionTypes.Condition)
		for k, v := range m {
			bs, err := v.AsBytes()
			if err != nil {
				return nil, errors.Wrapf(err, "as bytes %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("%s#detection#%s", ecosystem, rootID), k))
			}

			var conds []conditionTypes.Condition
			if err := util.Unmarshal(bs, &conds); err != nil {
				return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("%s#detection#%s", ecosystem, rootID), k))
			}
			cm[sourceTypes.SourceID(k)] = conds
		}

		ds = append(ds, dbTypes.VulnerabilityDataDetection{
			Ecosystem: ecosystem,
			Contents:  map[dataTypes.RootID]map[sourceTypes.SourceID][]conditionTypes.Condition{rootID: cm},
		})
	}

	return ds, nil
}

func (c *Connection) getAdvisory(ctx context.Context, id advisoryContentTypes.AdvisoryID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, error) {
	m, err := c.conn.Do(ctx, c.conn.B().Hgetall().Key(fmt.Sprintf("vulnerability#advisory#%s", id)).Build()).AsMap()
	if err != nil {
		return nil, errors.Wrapf(err, "HGETALL %s", fmt.Sprintf("vulnerability#advisory#%s", id))
	}
	if len(m) == 0 {
		return nil, nil
	}

	am := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory)
	for k, v := range m {
		ds, rootID, ok := strings.Cut(k, "#")
		if !ok {
			return nil, errors.Errorf("unexpected field format. expected: %s, actual: %s -> %s", "<Source ID>#<Root ID>", fmt.Sprintf("vulnerability#advisory#%s", id), k)
		}

		bs, err := v.AsBytes()
		if err != nil {
			return nil, errors.Wrapf(err, "as bytes %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("vulnerability#advisory#%s", id), k))
		}

		var as []advisoryTypes.Advisory
		if err := util.Unmarshal(bs, &as); err != nil {
			return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("vulnerability#advisory#%s", id), k))
		}

		if am[sourceTypes.SourceID(ds)] == nil {
			am[sourceTypes.SourceID(ds)] = make(map[dataTypes.RootID][]advisoryTypes.Advisory)
		}
		am[sourceTypes.SourceID(ds)][dataTypes.RootID(rootID)] = as
	}

	return am, nil
}

func (c *Connection) getVulnerability(ctx context.Context, id vulnerabilityContentTypes.VulnerabilityID) (map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, error) {
	m, err := c.conn.Do(ctx, c.conn.B().Hgetall().Key(fmt.Sprintf("vulnerability#vulnerability#%s", id)).Build()).AsMap()
	if err != nil {
		return nil, errors.Wrapf(err, "HGETALL %s", fmt.Sprintf("vulnerability#vulnerability#%s", id))
	}
	if len(m) == 0 {
		return nil, nil
	}

	vm := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
	for k, v := range m {
		ds, rootID, ok := strings.Cut(k, "#")
		if !ok {
			return nil, errors.Errorf("unexpected field format. expected: %s, actual: %s -> %s", "<Source ID>#<Root ID>", fmt.Sprintf("vulnerability#advisory#%s", id), k)
		}

		bs, err := v.AsBytes()
		if err != nil {
			return nil, errors.Wrapf(err, "as bytes %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("vulnerability#vulnerability#%s", id), k))
		}

		var vs []vulnerabilityTypes.Vulnerability
		if err := util.Unmarshal(bs, &vs); err != nil {
			return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("%s -> %s", fmt.Sprintf("vulnerability#vulnerability#%s", id), k))
		}

		if vm[sourceTypes.SourceID(ds)] == nil {
			vm[sourceTypes.SourceID(ds)] = make(map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
		}
		vm[sourceTypes.SourceID(ds)][dataTypes.RootID(rootID)] = vs
	}

	return vm, nil
}

func (c *Connection) getRoot(ctx context.Context, id dataTypes.RootID) (vulnerabilityRoot, error) {
	bs, err := c.conn.Do(ctx, c.conn.B().Get().Key(fmt.Sprintf("vulnerability#root#%s", id)).Build()).AsBytes()
	if err != nil {
		if rueidis.IsRedisNil(err) {
			return vulnerabilityRoot{}, nil
		}
		return vulnerabilityRoot{}, errors.Wrapf(err, "GET %s", fmt.Sprintf("vulnerability#root#%s", id))
	}

	var r vulnerabilityRoot
	if err := util.Unmarshal(bs, &r); err != nil {
		return vulnerabilityRoot{}, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability#root#%s", id))
	}

	return r, nil
}

func (c *Connection) PutVulnerabilityData(root string) error {
	ctx := context.TODO()

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

		if err := c.putDetection(ctx, data); err != nil {
			return errors.Wrap(err, "put detection")
		}

		if err := c.putAdvisory(ctx, data); err != nil {
			return errors.Wrap(err, "put advisory")
		}

		if err := c.putVulnerability(ctx, data); err != nil {
			return errors.Wrap(err, "put vulnerability")
		}

		if err := c.putRoot(ctx, data); err != nil {
			return errors.Wrap(err, "put root")
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", root)
	}

	return nil
}

func (c *Connection) putDetection(ctx context.Context, data dataTypes.Data) error {
	for _, d := range data.Detections {
		bs, err := util.Marshal(d.Conditions)
		if err != nil {
			return errors.Wrap(err, "marshal conditions")
		}

		if err := c.conn.Do(ctx, c.conn.B().Hset().Key(fmt.Sprintf("%s#detection#%s", d.Ecosystem, data.ID)).FieldValue().FieldValue(string(data.DataSource.ID), string(bs)).Build()).Error(); err != nil {
			return errors.Wrapf(err, "HSET %s %s %q", fmt.Sprintf("%s#detection#%s", d.Ecosystem, data.ID), data.DataSource.ID, string(bs))
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
			if err := c.conn.Do(ctx, c.conn.B().Sadd().Key(fmt.Sprintf("%s#index#%s", d.Ecosystem, p)).Member(string(data.ID)).Build()).Error(); err != nil {
				return errors.Wrapf(err, "SADD %s %s", fmt.Sprintf("%s#index#%s", d.Ecosystem, p), data.ID)
			}
		}
	}

	return nil
}

func (c *Connection) putAdvisory(ctx context.Context, data dataTypes.Data) error {
	m := make(map[advisoryContentTypes.AdvisoryID][]advisoryTypes.Advisory)
	for _, a := range data.Advisories {
		m[a.Content.ID] = append(m[a.Content.ID], a)
	}

	for id, as := range m {
		bs, err := util.Marshal(as)
		if err != nil {
			return errors.Wrap(err, "marshal advisories")
		}

		if err := c.conn.Do(ctx, c.conn.B().Hset().Key(fmt.Sprintf("vulnerability#advisory#%s", id)).FieldValue().FieldValue(fmt.Sprintf("%s#%s", data.DataSource.ID, data.ID), string(bs)).Build()).Error(); err != nil {
			return errors.Wrapf(err, "HSET %s %s %q", fmt.Sprintf("vulnerability#advisory#%s", id), fmt.Sprintf("%s#%s", data.DataSource.ID, data.ID), string(bs))
		}
	}

	return nil
}

func (c *Connection) putVulnerability(ctx context.Context, data dataTypes.Data) error {
	m := make(map[vulnerabilityContentTypes.VulnerabilityID][]vulnerabilityTypes.Vulnerability)
	for _, v := range data.Vulnerabilities {
		m[v.Content.ID] = append(m[v.Content.ID], v)
	}

	for id, vs := range m {
		bs, err := util.Marshal(vs)
		if err != nil {
			return errors.Wrap(err, "marshal vulnerabilities")
		}

		if err := c.conn.Do(ctx, c.conn.B().Hset().Key(fmt.Sprintf("vulnerability#vulnerability#%s", id)).FieldValue().FieldValue(fmt.Sprintf("%s#%s", data.DataSource.ID, data.ID), string(bs)).Build()).Error(); err != nil {
			return errors.Wrapf(err, "HSET %s %s %q", fmt.Sprintf("vulnerability#vulnerability#%s", id), fmt.Sprintf("%s#%s", data.DataSource.ID, data.ID), string(bs))
		}
	}

	return nil
}

func (c *Connection) putRoot(ctx context.Context, data dataTypes.Data) error {
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

	bs, err := c.conn.Do(ctx, c.conn.B().Get().Key(fmt.Sprintf("vulnerability#root#%s", data.ID)).Build()).AsBytes()
	if err != nil && !rueidis.IsRedisNil(err) {
		return errors.Wrapf(err, "GET %s", fmt.Sprintf("vulnerability#root#%s", data.ID))
	}

	if len(bs) > 0 {
		var r vulnerabilityRoot
		if err := util.Unmarshal(bs, &r); err != nil {
			return errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("vulnerability#root#%s", r.ID))
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

	bs, err = util.Marshal(root)
	if err != nil {
		return errors.Wrap(err, "marshal root")
	}

	if err := c.conn.Do(ctx, c.conn.B().Set().Key(fmt.Sprintf("vulnerability#root#%s", data.ID)).Value(string(bs)).Build()).Error(); err != nil {
		return errors.Wrapf(err, "SET %s %q", fmt.Sprintf("vulnerability#root#%s", data.ID), string(bs))
	}

	return nil
}

func (c *Connection) GetDataSource(id sourceTypes.SourceID) (*datasourceTypes.DataSource, error) {
	bs, err := c.conn.Do(context.TODO(), c.conn.B().Hget().Key("datasource").Field(string(id)).Build()).AsBytes()
	if err != nil {
		return nil, errors.Wrapf(err, "HGET %s %s", "datasource", id)
	}

	var v datasourceTypes.DataSource
	if err := util.Unmarshal(bs, &v); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %s", fmt.Sprintf("datasource -> %s", id))
	}

	return &v, nil
}

func (c *Connection) PutDataSource(root string) error {
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

	if err := c.conn.Do(context.TODO(), c.conn.B().Hset().Key("datasource").FieldValue().FieldValue(string(datasource.ID), string(bs)).Build()).Error(); err != nil {
		return errors.Wrapf(err, "HSET %s %s %q", "datasource", datasource.ID, string(bs))
	}

	return nil
}

func (c *Connection) DeleteAll() error {
	if err := c.conn.Do(context.TODO(), c.conn.B().Flushdb().Build()).Error(); err != nil {
		return errors.Wrap(err, "FLUSHDB")
	}

	return nil
}

func (c *Connection) Initialize() error {
	return nil
}
