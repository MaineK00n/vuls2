VERSION := $(shell git describe --tags --abbrev=0)
ifeq ($(VERSION), )
	VERSION := $(shell git rev-parse --abbrev-ref HEAD)
endif
ifeq ($(shell git rev-parse --abbrev-ref HEAD), nightly)
	VERSION := nightly
endif
REVISION := $(shell git rev-parse --short HEAD)
LDFLAGS := -ldflags "-s -w -X=github.com/MaineK00n/vuls2/pkg/version.Version=$(VERSION) -X=github.com/MaineK00n/vuls2/pkg/version.Revision=$(REVISION)"

GOPATH := $(shell go env GOPATH)
GOBIN := $(GOPATH)/bin

$(GOBIN)/golangci-lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

.PHONY: build
build: 
	go build $(LDFLAGS) ./cmd/vuls

.PHONY: install
install: 
	go install $(LDFLAGS) ./cmd/vuls

.PHONY: test
test: pretest
	go test -race ./...

.PHONY: pretest
pretest: lint vet fmtcheck

.PHONY: lint
lint: $(GOBIN)/golangci-lint
	golangci-lint run

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmtcheck
fmtcheck:
	gofmt -s -d .

BRANCH := main
DBTYPE := boltdb
DBPATH := ~/.cache/vuls/vuls.db

.PHONY: db-build
db-build:
	vuls db init --dbtype ${DBTYPE} --dbpath ${DBPATH}
	make db-add REPO=vuls-data-extracted-alma-errata BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-alpine-secdb BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-amazon BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-arch BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-cisa-kev BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-epss BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-freebsd BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-mitre-v5 BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-nvd-api-cve BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-oracle BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-redhat-vex-rhel BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-rocky-errata BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}

.PHONY: db-add
db-add: 
	vuls-data-update dotgit pull --dir . --restore ghcr.io/vulsio/vuls-data-db:${REPO}

	cat ${REPO}/datasource.json | jq --arg hash $$(git -C ${REPO} rev-parse HEAD) --arg date $$(git -C ${REPO} show -s --format=%at | xargs -I{} date -d @{} --utc +%Y-%m-%dT%TZ) '.extracted.commit |= $$hash | .extracted.date |= $$date' > tmp
	mv tmp ${REPO}/datasource.json
	vuls db add --dbtype ${DBTYPE} --dbpath ${DBPATH} ${REPO}
	rm -rf ${REPO}
