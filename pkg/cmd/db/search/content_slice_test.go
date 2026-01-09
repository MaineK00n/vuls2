package search_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/MaineK00n/vuls2/pkg/cmd/db/search"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
)

func setUpCSFlagSet(cs *[]dbTypes.FilterContentType) *pflag.FlagSet {
	f := pflag.NewFlagSet("test", pflag.ContinueOnError)
	f.VarP(search.NewContentSliceValue(nil, cs), "cs", "", "Test content slice flag")
	return f
}

func setUpCSFlagSetWithDefault(cs *[]dbTypes.FilterContentType) *pflag.FlagSet {
	f := pflag.NewFlagSet("test", pflag.ContinueOnError)
	f.VarP(search.NewContentSliceValue(*cs, cs), "cs", "", "Test content slice flag")
	return f
}

func TestCS(t *testing.T) {
	var cs []dbTypes.FilterContentType
	f := setUpCSFlagSet(&cs)

	vals := []dbTypes.FilterContentType{dbTypes.FilterContentTypeAdvisories, dbTypes.FilterContentTypeDataSources}
	ss := make([]string, 0, len(vals))
	for _, v := range vals {
		ss = append(ss, v.String())
	}
	arg := fmt.Sprintf("--cs=%s", strings.Join(ss, ","))
	err := f.Parse([]string{arg})
	if err != nil {
		t.Fatal("expected no error; got", err)
	}
	for i, v := range cs {
		if vals[i] != v {
			t.Fatalf("expected cs[%d] to be %s but got: %s", i, vals[i], v)
		}
	}
}

func TestCSDefault(t *testing.T) {
	var ss []dbTypes.FilterContentType
	f := setUpCSFlagSetWithDefault(&ss)

	vals := []dbTypes.FilterContentType{dbTypes.FilterContentTypeAdvisories, dbTypes.FilterContentTypeDataSources}

	err := f.Parse([]string{})
	if err != nil {
		t.Fatal("expected no error; got", err)
	}
	for i, v := range ss {
		if vals[i] != v {
			t.Fatalf("expected ss[%d] to be %s but got: %s", i, vals[i], v)
		}
	}
}

func TestCSWithDefault(t *testing.T) {
	var cs []dbTypes.FilterContentType
	f := setUpCSFlagSetWithDefault(&cs)

	vals := []dbTypes.FilterContentType{dbTypes.FilterContentTypeVulnerabilities, dbTypes.FilterContentTypeDetections}
	ss := make([]string, 0, len(vals))
	for _, v := range vals {
		ss = append(ss, v.String())
	}
	arg := fmt.Sprintf("--cs=%s", strings.Join(ss, ","))
	err := f.Parse([]string{arg})
	if err != nil {
		t.Fatal("expected no error; got", err)
	}
	for i, v := range cs {
		if vals[i] != v {
			t.Fatalf("expected cs[%d] to be %s but got: %s", i, vals[i], v)
		}
	}
}

func TestCSCalledTwice(t *testing.T) {
	var cs []dbTypes.FilterContentType
	f := setUpCSFlagSet(&cs)

	in := []string{"advisories,vulnerabilities", "detections"}
	expected := []dbTypes.FilterContentType{dbTypes.FilterContentTypeAdvisories, dbTypes.FilterContentTypeVulnerabilities, dbTypes.FilterContentTypeDetections}
	argfmt := "--cs=%s"
	arg1 := fmt.Sprintf(argfmt, in[0])
	arg2 := fmt.Sprintf(argfmt, in[1])
	err := f.Parse([]string{arg1, arg2})
	if err != nil {
		t.Fatal("expected no error; got", err)
	}

	if len(expected) != len(cs) {
		t.Fatalf("expected number of cs to be %d but got: %d", len(expected), len(cs))
	}
	for i, v := range cs {
		if expected[i] != v {
			t.Fatalf("expected cs[%d] to be %s but got: %s", i, expected[i], v)
		}
	}
}

func TestCSWithComma(t *testing.T) {
	var cs []dbTypes.FilterContentType
	f := setUpCSFlagSet(&cs)

	in := []string{`"advisories"`, `"vulnerabilities,detections",datasources`}
	argfmt := "--ss=%s"
	arg1 := fmt.Sprintf(argfmt, in[0])
	arg2 := fmt.Sprintf(argfmt, in[1])
	err := f.Parse([]string{arg1, arg2})
	if err == nil {
		t.Fatal("expected error; got no error")
	}
}

func TestCSAsSliceValue(t *testing.T) {
	var cs []dbTypes.FilterContentType
	f := setUpCSFlagSetWithDefault(&cs)

	err := f.Parse([]string{"--cs=vulnerabilities"})
	if err != nil {
		t.Fatal("expected no error; got", err)
	}

	f.VisitAll(func(f *pflag.Flag) {
		if val, ok := f.Value.(pflag.SliceValue); ok {
			_ = val.Replace([]string{"detections"})
		}
	})
	if len(cs) != 1 || cs[0] != dbTypes.FilterContentTypeDetections {
		t.Fatalf("Expected cs to be overwritten with 'detections', but got: %s", cs)
	}
}
