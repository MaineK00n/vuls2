package validate

import (
	"fmt"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
)

var affectedRangeRule = CriteriaRule{
	Name:        "affected-range",
	Description: "version criterion: affected with a range type declares at least one range",
	Criterion:   inspectAffectedRange,
}

// inspectAffectedRange reports version criterions whose affected declares a
// range type but carries no range entry: such an affected can never match a
// version, so the criterion is dead data. An affected without a type is left
// alone — fixed-only affected exist and evaluation does not read Type then.
func inspectAffectedRange(ctx CriteriaContext, cn criterionTypes.Criterion) []Violation {
	if cn.Type != criterionTypes.CriterionTypeVersion || cn.Version == nil || cn.Version.Affected == nil {
		return nil
	}

	var unset rangeTypes.RangeType
	if a := cn.Version.Affected; a.Type != unset && len(a.Range) == 0 {
		return []Violation{{
			Pointer: fmt.Sprintf("%s/version/affected", ctx.Pointer),
			Message: fmt.Sprintf("%s: affected: type %q but no range", ctx.At, a.Type),
		}}
	}
	return nil
}
