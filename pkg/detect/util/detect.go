package util

import (
	"context"
	"iter"

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

// RootDetection is one streamed element of Detect: a single rootID's
// detection with its full FilteredCriteria trees.
type RootDetection struct {
	RootID    dataTypes.RootID
	Detection detectTypes.VulnerabilityDataDetection
}

// Detect looks up the rootIDs matching queries through the index and
// yields each rootID's detection as its worker finishes, in completion
// order. Every condition passes through unconditionally with its full
// criteria tree — the per-condition affected/unaffected gating is the
// consumer's policy (top-level pkg/detect.Detect gates on Affected; other
// consumers may prune or project per element while only the in-flight
// trees are live).
//
// A yielded non-nil error (index lookup or worker failure) is terminal:
// the sequence stops after it. Breaking out of the loop early stops the
// pipeline promptly, not instantly: no further elements are yielded and no
// new DB / criteria work is started (a request already waiting for a
// worker slot may still be scheduled, but returns before doing any work),
// while workers already mid-element finish their current DB fetch /
// criteria evaluation and observe the cancellation at their result-send
// boundary; their results are discarded.
//
// Consumers that need the whole result at once accumulate the sequence
// into a map; consumers that reduce each rootID's trees (pruning,
// projection) fold elements as they arrive, so peak memory holds the
// folded result plus only the in-flight trees rather than every rootID's
// full tree.
func Detect(s session.Storage, ecosystem ecosystemTypes.Ecosystem, queries []string, createRequestFn func(rootID dataTypes.RootID, queries []string) Request, concurrency int) iter.Seq2[RootDetection, error] {
	return func(yield func(RootDetection, error) bool) {
		m := make(map[dataTypes.RootID][]string)
		for _, q := range queries {
			rs, err := s.GetIndex(ecosystem, q)
			if err != nil {
				if errors.Is(err, dbTypes.ErrNotFoundIndex) {
					continue
				}
				yield(RootDetection{}, errors.Wrap(err, "get index"))
				return
			}
			for _, r := range rs {
				m[r] = append(m[r], q)
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		reqChan := make(chan Request, concurrency)
		go func() {
			defer close(reqChan)
			for rootID, names := range m {
				select {
				case reqChan <- createRequestFn(rootID, names):
				case <-ctx.Done():
					return
				}
			}
		}()

		// Buffered to concurrency, not len(m): workers block on send when
		// the consumer lags, bounding the number of full trees in flight.
		// Sends select on ctx.Done so an early break unblocks them.
		resChan := make(chan RootDetection, concurrency)

		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(concurrency)

		done := make(chan error, 1)
		go func() {
			for req := range reqChan {
				// Once the pipeline is canceled (early break or a worker
				// error), keep draining reqChan so the producer can exit,
				// but stop scheduling workers: requests already buffered
				// must not trigger DB fetch / criteria work whose result
				// would only be discarded.
				if gctx.Err() != nil {
					continue
				}
				g.Go(func() error {
					// The dispatcher's check above is not atomic with g.Go:
					// with SetLimit, g.Go blocks while every slot is taken,
					// and a cancellation arriving during that wait would
					// otherwise let this request start once a slot opens.
					// Re-check before doing any DB / criteria work.
					if err := gctx.Err(); err != nil {
						return err
					}

					m, err := s.GetDetection(ecosystem, req.RootID)
					if err != nil {
						return errors.Wrap(err, "get detection")
					}

					d := detectTypes.VulnerabilityDataDetection{
						Ecosystem: ecosystem,
						Contents:  make(map[sourceTypes.SourceID][]conditionTypes.FilteredCondition),
					}
					for sourceID, conds := range m {
						for _, cond := range conds {
							fcond, err := cond.Accept(req.Query)
							if err != nil {
								return errors.Wrap(err, "criteria accept")
							}

							fcond.Criteria, err = replaceIndexes(fcond.Criteria, req.Indexes)
							if err != nil {
								return errors.Wrap(err, "replace indexes")
							}

							d.Contents[sourceID] = append(d.Contents[sourceID], fcond)
						}
					}

					if len(d.Contents) == 0 {
						return nil
					}

					select {
					case resChan <- RootDetection{RootID: req.RootID, Detection: d}:
						return nil
					case <-gctx.Done():
						return gctx.Err()
					}
				})
			}
			done <- g.Wait()
			close(resChan)
		}()

		for rd := range resChan {
			if !yield(rd, nil) {
				// cancel (deferred) unblocks the producer and the workers'
				// sends; the dispatch goroutine then drains and exits on
				// its own.
				return
			}
		}

		if err := <-done; err != nil {
			yield(RootDetection{}, errors.Wrap(err, "err in goroutine"))
		}
	}
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
