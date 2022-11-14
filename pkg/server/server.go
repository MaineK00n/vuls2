package server

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/MaineK00n/vuls2/pkg/cmd/version"
	"github.com/MaineK00n/vuls2/pkg/config"
	"github.com/MaineK00n/vuls2/pkg/detect"
	"github.com/MaineK00n/vuls2/pkg/scan/os"
	"github.com/MaineK00n/vuls2/pkg/scan/ospkg/apk"
	"github.com/MaineK00n/vuls2/pkg/scan/ospkg/dpkg"
	"github.com/MaineK00n/vuls2/pkg/scan/ospkg/rpm"
	"github.com/MaineK00n/vuls2/pkg/types"
)

type scanContents struct {
	Contents []struct {
		ContentType string `json:"content_type,omitempty"`
		Content     string `json:"content,omitempty"`
	} `json:"contents,omitempty"`
}

func Scan() echo.HandlerFunc {
	return func(c echo.Context) error {
		s := new(scanContents)
		if err := c.Bind(s); err != nil {
			return c.JSON(http.StatusBadRequest, "bad request")
		}

		h := types.Host{Name: uuid.NewString()}

		for _, cont := range s.Contents {
			switch cont.ContentType {
			case "os-release":
				family, release, err := os.ParseOSRelease(cont.Content)
				if err != nil {
					h.ScanError = err.Error()
					return c.JSON(http.StatusInternalServerError, h)
				}
				h.Family = family
				h.Release = release
			case "apk":
				pkgs, err := apk.ParseInstalledPackage(cont.Content)
				if err != nil {
					h.ScanError = err.Error()
					return c.JSON(http.StatusInternalServerError, h)
				}
				h.Packages.OSPkg = pkgs
			case "dpkg":
				pkgs, err := dpkg.ParseInstalledPackage(cont.Content)
				if err != nil {
					h.ScanError = err.Error()
					return c.JSON(http.StatusInternalServerError, h)
				}
				h.Packages.OSPkg = pkgs
			case "rpm":
				pkgs, err := rpm.ParseInstalledPackage(cont.Content)
				if err != nil {
					h.ScanError = err.Error()
					return c.JSON(http.StatusInternalServerError, h)
				}
				h.Packages.OSPkg = pkgs
			}
		}

		t := time.Now()
		h.ScannedAt = &t
		h.ScannedVersion = version.Version
		h.ScannedRevision = version.Revision
		return c.JSON(http.StatusOK, h)
	}
}

func Detect(dbpath string) echo.HandlerFunc {
	return func(c echo.Context) error {
		h := new(types.Host)
		if err := c.Bind(h); err != nil {
			return c.JSON(http.StatusBadRequest, "bad request")
		}

		if h.Config.Detect == nil {
			h.Config.Detect = &config.Detect{}
		}
		h.Config.Detect.Path = dbpath

		if err := detect.Detect(context.Background(), h); err != nil {
			h.DetectError = err.Error()
			return c.JSON(http.StatusInternalServerError, h)
		}

		return c.JSON(http.StatusOK, h)
	}
}
