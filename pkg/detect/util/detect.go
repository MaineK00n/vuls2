package util

import (
	"context"
	"maps"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
)

type Request struct {
	RootID  dataTypes.RootID
	Query   criterionTypes.Query
	Indexes []int
}

func Detect(s session.Storage, ecosystem ecosystemTypes.Ecosystem, queries []string, createRequestFn func(rootID dataTypes.RootID, queries []string) Request, concurrency int) (map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection, error) {
	m := make(map[dataTypes.RootID][]string)
	for _, q := range queries {
		rs, err := s.GetIndex(ecosystem, q)
		if err != nil {
			if errors.Is(err, dbTypes.ErrNotFoundIndex) {
				continue
			}
			return nil, errors.Wrap(err, "get index")
		}
		for _, r := range rs {
			m[r] = append(m[r], q)
		}
	}

	reqChan := make(chan Request, concurrency)
	go func() {
		defer close(reqChan)
		for rootID, names := range m {
			reqChan <- createRequestFn(rootID, names)
		}
	}()

	resChan := make(chan map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection, len(m))

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(concurrency)
	for req := range reqChan {
		g.Go(func() error {
			m, err := s.GetDetection(ecosystem, req.RootID)
			if err != nil {
				return errors.Wrap(err, "get detection")
			}

			dm := make(map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection)
			for sourceID, conds := range m {
				for _, cond := range conds {
					fcond, err := cond.Accept(req.Query)
					if err != nil {
						return errors.Wrap(err, "criteria accept")
					}

					// Pass every condition through unconditionally. The
					// per-condition affected/unaffected gating is moved to the
					// top-level pkg/detect.Detect, so that consumers calling
					// this function directly (or via ospkg.Detect / cpe.Detect)
					// can apply their own pruning / ecosystem-specific filter
					// over the full FilteredCriteria tree.
					fcond.Criteria, err = replaceIndexes(fcond.Criteria, req.Indexes)
					if err != nil {
						return errors.Wrap(err, "replace indexes")
					}

					d, ok := dm[req.RootID]
					if !ok {
						d = detectTypes.VulnerabilityDataDetection{
							Ecosystem: ecosystem,
							Contents:  make(map[sourceTypes.SourceID][]conditionTypes.FilteredCondition),
						}
					}
					d.Contents[sourceID] = append(d.Contents[sourceID], fcond)
					dm[req.RootID] = d
				}
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				resChan <- dm
				return nil
			}
		})
	}

	go func() {
		g.Wait() //nolint:errcheck
		close(resChan)
	}()

	dm := make(map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection)
	for res := range resChan {
		maps.Copy(dm, res)
	}

	if err := g.Wait(); err != nil {
		return nil, errors.Wrap(err, "err in goroutine")
	}

	return dm, nil
}

func replaceIndexes(fca criteriaTypes.FilteredCriteria, indexes []int) (criteriaTypes.FilteredCriteria, error) {
	replaced := criteriaTypes.FilteredCriteria{Operator: fca.Operator, Repositories: fca.Repositories}

	for _, ca := range fca.Criterias {
		rca, err := replaceIndexes(ca, indexes)
		if err != nil {
			return criteriaTypes.FilteredCriteria{}, errors.Wrap(err, "replace indexes")
		}
		replaced.Criterias = append(replaced.Criterias, rca)
	}

	for _, cn := range fca.Criterions {
		switch cn.Criterion.Type {
		case criterionTypes.CriterionTypeVersion:
			is := make([]int, 0, len(cn.Accepts.Version))
			for _, a := range cn.Accepts.Version {
				is = append(is, indexes[a])
			}
			cn.Accepts.Version = is
			replaced.Criterions = append(replaced.Criterions, cn)
		case criterionTypes.CriterionTypeNoneExist:
			replaced.Criterions = append(replaced.Criterions, cn)
		case criterionTypes.CriterionTypeKB:
			replaced.Criterions = append(replaced.Criterions, cn)
		case criterionTypes.CriterionTypeCPE:
			exact := make([]int, 0, len(cn.Accepts.CPE.Exact))
			for _, a := range cn.Accepts.CPE.Exact {
				exact = append(exact, indexes[a])
			}
			cn.Accepts.CPE.Exact = exact
			versionUnconfirmed := make([]int, 0, len(cn.Accepts.CPE.VersionUnconfirmed))
			for _, a := range cn.Accepts.CPE.VersionUnconfirmed {
				versionUnconfirmed = append(versionUnconfirmed, indexes[a])
			}
			cn.Accepts.CPE.VersionUnconfirmed = versionUnconfirmed
			replaced.Criterions = append(replaced.Criterions, cn)
		default:
			// A type in this build's vocabulary reaching this default means
			// the vocabulary gained a criterion type without this switch
			// gaining its remap arm — a bug in this build, not newer data:
			// its accepted indexes would silently go un-remapped. Fail
			// loudly, mirroring the upstream dispatch contract.
			if cn.Criterion.Type.Known() {
				return criteriaTypes.FilteredCriteria{}, errors.Errorf("unexpected criterion type. expected: %q, actual: %q", criterionTypes.CriterionTypes(), cn.Criterion.Type)
			}
			// A criterion type outside this build's vocabulary (data from a
			// newer vuls-data-update): Accept degraded it to a non-match and
			// recorded the skip on FilteredCriterion.Warnings, so it accepted
			// no queries and there are no indexes to remap — pass it through
			// unchanged to keep the recorded skip observable downstream.
			replaced.Criterions = append(replaced.Criterions, cn)
		}
	}

	return replaced, nil
}
