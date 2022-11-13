package debian

import (
	"context"
	"fmt"

	version "github.com/knqyf263/go-deb-version"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/MaineK00n/vuls2/pkg/db"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/types"
	"github.com/MaineK00n/vuls2/pkg/types"
)

type Detector struct{}

func (d Detector) Name() string {
	return "debian detector"
}

func (d Detector) Detect(ctx context.Context, host *types.Host) error {
	if host.ScannedCves == nil {
		host.ScannedCves = map[string]types.VulnInfo{}
	}

	vulndb, err := db.Open("boltdb", host.Config.Detect.Path, false)
	if err != nil {
		return errors.Wrapf(err, "open %s", host.Config.Detect.Path)
	}
	defer vulndb.Close()

	srcpkgs := map[string]string{}
	for _, p := range host.Packages.OSPkg {
		srcpkgs[p.SrcName] = p.SrcVersion
	}

	for srcname, srcver := range srcpkgs {
		pkgs, err := vulndb.GetPackage(host.Family, host.Release, srcname)
		if err != nil {
			return errors.Wrap(err, "get package")
		}

		for cveid, datasrcs := range pkgs {
			for datasrc, ps := range datasrcs {
				for id, p := range ps {
					switch p.Status {
					case "fixed":
						for _, andVs := range p.Version {
							affected := true
							for _, v := range andVs {
								r, err := compare(v.Operator, srcver, v.Version)
								if err != nil {
									return errors.Wrap(err, "compare")
								}
								if !r {
									affected = false
									break
								}
							}
							if affected {
								vinfo, ok := host.ScannedCves[cveid]
								if !ok {
									host.ScannedCves[cveid] = types.VulnInfo{ID: cveid}
								}
								vinfo.AffectedPackages = append(vinfo.AffectedPackages, types.AffectedPackage{
									Name:   srcname,
									Source: fmt.Sprintf("%s:%s", datasrc, id),
									Status: p.Status,
								})
								host.ScannedCves[cveid] = vinfo
							}
						}
					case "open":
						vinfo, ok := host.ScannedCves[cveid]
						if !ok {
							host.ScannedCves[cveid] = types.VulnInfo{ID: cveid}
						}
						vinfo.AffectedPackages = append(vinfo.AffectedPackages, types.AffectedPackage{
							Name:   srcname,
							Source: fmt.Sprintf("%s:%s", datasrc, id),
							Status: p.Status,
						})
						host.ScannedCves[cveid] = vinfo
					case "not affected":
					}
				}
			}
		}
	}

	vulns, err := vulndb.GetVulnerability(maps.Keys(host.ScannedCves))
	if err != nil {
		return errors.Wrap(err, "get vulnerability")
	}
	for cveid, datasrcs := range vulns {
		vinfo := host.ScannedCves[cveid]
		vinfo.Content = map[string]dbTypes.Vulnerability{}
		for src, v := range datasrcs {
			vinfo.Content[src] = v
		}
		host.ScannedCves[cveid] = vinfo
	}

	return nil
}

func compare(operator, srcver, ver string) (bool, error) {
	v1, err := version.NewVersion(srcver)
	if err != nil {
		return false, errors.Wrap(err, "parse version")
	}
	v2, err := version.NewVersion(ver)
	if err != nil {
		return false, errors.Wrap(err, "parse version")
	}

	r := v1.Compare(v2)
	switch operator {
	case "eq":
		if r == 0 {
			return true, nil
		}
		return false, nil
	case "lt":
		if r < 0 {
			return true, nil
		}
		return false, nil
	case "le":
		if r <= 0 {
			return true, nil
		}
		return false, nil
	case "gt":
		if r > 0 {
			return true, nil
		}
		return false, nil
	case "ge":
		if r >= 0 {
			return true, nil
		}
		return false, nil
	default:
		return false, errors.New("not supported operator")
	}
}
