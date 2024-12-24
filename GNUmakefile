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
	# make db-add REPO=vuls-data-extracted-alma-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-alma-oval BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-alpine-secdb BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-alpine-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-amazon BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-arch BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-debian-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-debian-oval BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-debian-security-tracker-api BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-debian-security-tracker-salsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-freebsd BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-gentoo BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-netbsd BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-oracle BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-cve BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-csaf BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-csaf-rhel BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-cvrf BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-ovalv1 BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-ovalv2 BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-ovalv2-rhel BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-redhat-vex BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-redhat-vex-rhel BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-rocky-errata BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-rocky-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-suse-oval BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-suse-cvrf BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-suse-csaf BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-ubuntu-oval BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-ubuntu-cve-tracker BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-windows-bulletin BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-windows-cvrf BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-windows-wsusscn2 BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}

	# make db-add REPO=vuls-data-extracted-cargo-ghsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-cargo-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-composer-ghsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-composer-glsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-composer-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-conan-glsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-erlang-ghsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-erlang-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-golang-ghsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-golang-glsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-golang-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-haskell-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-maven-ghsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-maven-glsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-maven-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-npm-ghsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-npm-glsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-npm-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nuget-ghsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nuget-glsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nuget-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-pip-ghsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-pip-glsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-pip-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-pub-ghsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-pub-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-r-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-rubygems-ghsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-rubygems-glsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-rubygems-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-swift-ghsa BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-swift-osv BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}

	# make db-add REPO=vuls-data-extracted-attack BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-capec BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-cwe BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-eol BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-epss BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-exploit-exploitdb BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-exploit-github BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-exploit-inthewild BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-exploit-trickest BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-jvn-feed-detail BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-jvn-feed-product BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-jvn-feed-rss BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-kev BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-mitre-cvrf BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-mitre-v4 BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-mitre-v5 BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-msf BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	make db-add REPO=vuls-data-extracted-nvd-api-cve BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nvd-api-cpe  BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nvd-api-cpematch BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nvd-feed-cve BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nvd-feed-cpe  BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-nvd-feed-cpematch BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}
	# make db-add REPO=vuls-data-extracted-snort BRANCH=${BRANCH} DBTYPE=${DBTYPE} DBPATH=${DBPATH}

.PHONY: db-add
db-add: 
	git clone -b ${BRANCH} --depth 1 https://github.com/vulsio/${REPO}.git
	find ${REPO} -name "*.json.*" | sed -r 's/(.*)\.json\.[0-9]+/\1.json/' | sort -u | \
	while read -r base; do \
		cat "$$base".* > "$$base" && rm -f "$$base".*; \
	done
	cat ${REPO}/datasource.json | jq --arg hash $$(git -C ${REPO} rev-parse HEAD) --arg date $$(git -C ${REPO} show -s --format=%at | xargs -I{} date -d @{} --utc +%Y-%m-%dT%TZ) '.extracted.commit |= $$hash | .extracted.date |= $$date' > tmp
	mv tmp ${REPO}/datasource.json
	vuls db add --dbtype ${DBTYPE} --dbpath ${DBPATH} ${REPO}
	rm -rf ${REPO}
