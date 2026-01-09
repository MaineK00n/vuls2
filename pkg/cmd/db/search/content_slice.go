package search

import (
	"bytes"
	"encoding/csv"
	"strings"

	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

// -- contentSlice Value
type contentSliceValue struct {
	value   *[]dbTypes.FilterContentType
	changed bool
}

func newContentSliceValue(val []dbTypes.FilterContentType, p *[]dbTypes.FilterContentType) *contentSliceValue {
	sv := new(contentSliceValue)
	sv.value = p
	*sv.value = val
	return sv
}

func readAsCSV(val string) ([]dbTypes.FilterContentType, error) {
	if val == "" {
		return []dbTypes.FilterContentType{}, nil
	}

	stringReader := strings.NewReader(val)
	csvReader := csv.NewReader(stringReader)
	ss, err := csvReader.Read()
	if err != nil {
		return []dbTypes.FilterContentType{}, err
	}

	cs := make([]dbTypes.FilterContentType, 0, len(ss))
	for _, s := range ss {
		c, err := dbTypes.NewFilterContentType(s)
		if err != nil {
			return []dbTypes.FilterContentType{}, err
		}
		cs = append(cs, c)
	}

	return cs, nil
}

func writeAsCSV(vals []dbTypes.FilterContentType) (string, error) {
	ss := make([]string, 0, len(vals))
	for _, v := range vals {
		ss = append(ss, v.String())
	}

	b := &bytes.Buffer{}
	w := csv.NewWriter(b)
	err := w.Write(ss)
	if err != nil {
		return "", err
	}
	w.Flush()
	return strings.TrimSuffix(b.String(), "\n"), nil
}

func (c *contentSliceValue) Set(val string) error {
	v, err := readAsCSV(val)
	if err != nil {
		return err
	}
	if !c.changed {
		*c.value = v
	} else {
		*c.value = append(*c.value, v...)
	}
	c.changed = true
	return nil
}

func (s *contentSliceValue) Type() string {
	return "contentSlice"
}

func (s *contentSliceValue) String() string {
	str, _ := writeAsCSV(*s.value)
	return "[" + str + "]"
}

func (s *contentSliceValue) Append(val string) error {
	c, err := dbTypes.NewFilterContentType(val)
	if err != nil {
		return err
	}

	*s.value = append(*s.value, c)
	return nil
}

func (s *contentSliceValue) Replace(val []string) error {
	cs := make([]dbTypes.FilterContentType, 0, len(val))
	for _, v := range val {
		c, err := dbTypes.NewFilterContentType(v)
		if err != nil {
			return err
		}
		cs = append(cs, c)
	}

	*s.value = cs
	return nil
}

func (s *contentSliceValue) GetSlice() []string {
	ss := make([]string, 0, len(*s.value))
	for _, v := range *s.value {
		ss = append(ss, v.String())
	}
	return ss
}
