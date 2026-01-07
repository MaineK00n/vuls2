package search

import (
	"slices"
	"strings"

	"github.com/pkg/errors"

	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

type filterContentOption struct {
	types []dbTypes.FilterContentType
}

func (c *filterContentOption) String() string {
	return strings.Join(c.GetSlice(), ",")
}

func (c *filterContentOption) Set(v string) error {
	for s := range strings.SplitSeq(v, ",") {
		if err := c.Append(strings.TrimSpace(s)); err != nil {
			return err
		}
	}

	return nil
}

func (c *filterContentOption) Type() string {
	return "FilterContentOption"
}

func (c *filterContentOption) Append(v string) error {
	t, err := dbTypes.NewFilterContentType(v)
	if err != nil {
		return errors.Wrap(err, "to filter content type")
	}

	// Append() should add the new content type to the end, and we don't want duplicates.
	// Deletes existing ones and appends again.
	// https://pkg.go.dev/github.com/spf13/pflag@v1.0.9#SliceValue.Append
	c.types = slices.DeleteFunc(c.types, func(ft dbTypes.FilterContentType) bool {
		return ft == t
	})
	c.types = append(c.types, t)
	return nil
}

func (c *filterContentOption) Replace(vs []string) error {
	c.types = nil

	for _, v := range vs {
		if err := c.Append(v); err != nil {
			return err
		}
	}
	return nil
}

func (c *filterContentOption) GetSlice() []string {
	if len(c.types) == 0 {
		return c.AllCandidates()
	}

	ss := make([]string, 0, len(c.types))
	for _, t := range c.types {
		ss = append(ss, t.String())
	}
	return ss
}

func (c *filterContentOption) ContentTypes() []dbTypes.FilterContentType {
	if len(c.types) == 0 {
		return dbTypes.AllFilterContentTypes()
	}

	return c.types
}

func (c *filterContentOption) AllCandidates() []string {
	var ss []string
	for _, t := range dbTypes.AllFilterContentTypes() {
		ss = append(ss, t.String())
	}
	return ss
}
