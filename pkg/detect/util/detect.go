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
	db "github.com/MaineK00n/vuls2/pkg/db/common"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
)

type Request struct {
	RootID  dataTypes.RootID
	Query   criterionTypes.Query
	Indexes []int
}

func Detect(dbc db.DB, ecosystem ecosystemTypes.Ecosystem, queries []string, createRequestFn func(rootID dataTypes.RootID, queries []string) Request, concurrency int) (map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection, error) {
	m, err := dbc.GetIndexes(ecosystem, queries...)
	if err != nil {
		return nil, errors.Wrap(err, "get indexes")
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
			m, err := dbc.GetDetection(ecosystem, req.RootID)
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

					isAffected, err := fcond.Affected()
					if err != nil {
						return errors.Wrap(err, "criteria affected")
					}
					if isAffected {
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
	replaced := criteriaTypes.FilteredCriteria{Operator: fca.Operator}

	for _, ca := range fca.Criterias {
		rca, err := replaceIndexes(ca, indexes)
		if err != nil {
			return criteriaTypes.FilteredCriteria{}, errors.Wrap(err, "replace indexes")
		}
		if len(rca.Criterias) == 0 && len(rca.Criterions) == 0 {
			continue
		}
		replaced.Criterias = append(replaced.Criterias, rca)
	}

	var cns []criterionTypes.FilteredCriterion
	for _, cn := range fca.Criterions {
		isAffected, err := cn.Affected()
		if err != nil {
			return criteriaTypes.FilteredCriteria{}, errors.Wrap(err, "criterion affected")
		}
		if !isAffected {
			continue
		}

		switch cn.Criterion.Type {
		case criterionTypes.CriterionTypeVersion:
			is := make([]int, 0, len(cn.Accepts.Version))
			for _, a := range cn.Accepts.Version {
				is = append(is, indexes[a])
			}
			cn.Accepts.Version = is
			cns = append(cns, cn)
		case criterionTypes.CriterionTypeNoneExist:
			cns = append(cns, cn)
		default:
			return criteriaTypes.FilteredCriteria{}, errors.Errorf("unexpected criterion type. expected: %q, actual: %q", []criterionTypes.CriterionType{criterionTypes.CriterionTypeVersion, criterionTypes.CriterionTypeNoneExist}, cn.Criterion.Type)
		}
	}
	replaced.Criterions = cns

	return replaced, nil
}
