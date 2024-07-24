VERSION := $(shell git describe --tags --abbrev=0)
ifeq ($(VERSION), )
	VERSION := $(shell git rev-parse --abbrev-ref HEAD)
endif
ifeq ($(shell git rev-parse --abbrev-ref HEAD), nightly)
	VERSION := nightly
endif
REVISION := $(shell git rev-parse --short HEAD)
LDFLAGS := -ldflags "-s -w -X=github.com/MaineK00n/vuls2/pkg/cmd/version.Version=$(VERSION) -X=github.com/MaineK00n/vuls2/pkg/cmd/version.Revision=$(REVISION)"

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

DBTYPE := boltdb
DBPATH := ~/.cache/vuls/vuls.db

.PHONY: db-build
db-build:
	vuls db init --dbtype ${DBTYPE} --dbpath ${DBPATH}
	make db-add REPO=vuls-data-extracted-alma-errata DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-alma-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-alma-oval DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-alpine-secdb DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-alpine-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-amazon DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-arch DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-debian-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-debian-oval DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-debian-security-tracker-api DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-debian-security-tracker-salsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-freebsd DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-gentoo DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-netbsd DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-oracle DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-cve DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-csaf DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-cvrf DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-ovalv1 DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-ovalv2 DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-vex DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-rocky-errata DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-rocky-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-suse-oval DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-suse-cvrf DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-suse-csaf DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-ubuntu-oval DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-ubuntu-cve-tracker DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-windows-bulletin DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-windows-cvrf DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-windows-wsusscn2 DBTYPE=${DBTYPE} DBPATH=${DBPATH}

	# make db-add REPO=vuls-data-extracted-cargo-ghsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-cargo-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-composer-ghsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-composer-glsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-composer-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-conan-glsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-erlang-ghsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-erlang-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-golang-ghsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-golang-glsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-golang-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-haskell-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-maven-ghsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-maven-glsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-maven-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-npm-ghsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-npm-glsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-npm-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nuget-ghsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nuget-glsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nuget-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-pip-ghsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-pip-glsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-pip-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-pub-ghsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-pub-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-r-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-rubygems-ghsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-rubygems-glsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-rubygems-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-swift-ghsa DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-swift-osv DBTYPE=${DBTYPE} DBPATH=${DBPATH}

	# make db-add REPO=vuls-data-extracted-attack DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-capec DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-cwe DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-eol DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-epss DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-exploit-exploitdb DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-exploit-github DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-exploit-inthewild DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-exploit-trickest DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-jvn-feed-detail DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-jvn-feed-product DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-jvn-feed-rss DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-kev DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-mitre-cvrf DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-mitre-v4 DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-mitre-v5 DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-msf DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nvd-feed-cve DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nvd-feed-cpe  DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nvd-feed-cpematch DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-snort DBTYPE=${DBTYPE} DBPATH=${DBPATH}

.PHONY: db-add
db-add: 
	git clone --depth 1 https://github.com/vulsio/${REPO}.git
	cat ${REPO}/datasource.json | jq --arg hash $$(git -C ${REPO} rev-parse HEAD) --arg date $$(git -C ${REPO} show -s --format=%at | xargs -I{} date -d @{} --utc +%Y-%m-%dT%TZ) '.extracted.commit |= $$hash | .extracted.date |= $$date' > tmp
	mv tmp ${REPO}/datasource.json
	vuls db add --dbtype ${DBTYPE} --dbpath ${DBPATH} ${REPO}
	rm -rf ${REPO}
