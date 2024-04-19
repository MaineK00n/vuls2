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

.PHONY: db-build
db-build:
	vuls db init
	make db-add REPO=vuls-data-extracted-alma-errata
	# make db-add REPO=vuls-data-extracted-alma-osv
	# make db-add REPO=vuls-data-extracted-alma-oval
	make db-add REPO=vuls-data-extracted-alpine-secdb
	# make db-add REPO=vuls-data-extracted-alpine-osv
	make db-add REPO=vuls-data-extracted-amazon
	make db-add REPO=vuls-data-extracted-arch
	# make db-add REPO=vuls-data-extracted-debian-osv
	# make db-add REPO=vuls-data-extracted-debian-oval
	# make db-add REPO=vuls-data-extracted-debian-security-tracker-api
	# make db-add REPO=vuls-data-extracted-debian-security-tracker-salsa
	make db-add REPO=vuls-data-extracted-freebsd
	# make db-add REPO=vuls-data-extracted-gentoo
	# make db-add REPO=vuls-data-extracted-netbsd
	# make db-add REPO=vuls-data-extracted-oracle
	# make db-add REPO=vuls-data-extracted-redhat-cve
	# make db-add REPO=vuls-data-extracted-redhat-csaf
	# make db-add REPO=vuls-data-extracted-redhat-cvrf
	# make db-add REPO=vuls-data-extracted-redhat-ovalv1
	# make db-add REPO=vuls-data-extracted-redhat-ovalv2
	# make db-add REPO=vuls-data-extracted-redhat-vex
	# make db-add REPO=vuls-data-extracted-rocky-errata
	# make db-add REPO=vuls-data-extracted-rocky-osv
	# make db-add REPO=vuls-data-extracted-suse-oval
	# make db-add REPO=vuls-data-extracted-suse-cvrf
	# make db-add REPO=vuls-data-extracted-suse-csaf
	# make db-add REPO=vuls-data-extracted-ubuntu-oval
	# make db-add REPO=vuls-data-extracted-ubuntu-cve-tracker
	# make db-add REPO=vuls-data-extracted-windows-bulletin
	# make db-add REPO=vuls-data-extracted-windows-cvrf
	# make db-add REPO=vuls-data-extracted-windows-wsusscn2

	# make db-add REPO=vuls-data-extracted-cargo-ghsa
	# make db-add REPO=vuls-data-extracted-cargo-osv
	# make db-add REPO=vuls-data-extracted-composer-ghsa
	# make db-add REPO=vuls-data-extracted-composer-glsa
	# make db-add REPO=vuls-data-extracted-composer-osv
	# make db-add REPO=vuls-data-extracted-conan-glsa
	# make db-add REPO=vuls-data-extracted-erlang-ghsa
	# make db-add REPO=vuls-data-extracted-erlang-osv
	# make db-add REPO=vuls-data-extracted-golang-ghsa
	# make db-add REPO=vuls-data-extracted-golang-glsa
	# make db-add REPO=vuls-data-extracted-golang-osv
	# make db-add REPO=vuls-data-extracted-haskell-osv
	# make db-add REPO=vuls-data-extracted-maven-ghsa
	# make db-add REPO=vuls-data-extracted-maven-glsa
	# make db-add REPO=vuls-data-extracted-maven-osv
	# make db-add REPO=vuls-data-extracted-npm-ghsa
	# make db-add REPO=vuls-data-extracted-npm-glsa
	# make db-add REPO=vuls-data-extracted-npm-osv
	# make db-add REPO=vuls-data-extracted-nuget-ghsa
	# make db-add REPO=vuls-data-extracted-nuget-glsa
	# make db-add REPO=vuls-data-extracted-nuget-osv
	# make db-add REPO=vuls-data-extracted-pip-ghsa
	# make db-add REPO=vuls-data-extracted-pip-glsa
	# make db-add REPO=vuls-data-extracted-pip-osv
	# make db-add REPO=vuls-data-extracted-pub-ghsa
	# make db-add REPO=vuls-data-extracted-pub-osv
	# make db-add REPO=vuls-data-extracted-r-osv
	# make db-add REPO=vuls-data-extracted-rubygems-ghsa
	# make db-add REPO=vuls-data-extracted-rubygems-glsa
	# make db-add REPO=vuls-data-extracted-rubygems-osv
	# make db-add REPO=vuls-data-extracted-swift-ghsa
	# make db-add REPO=vuls-data-extracted-swift-osv

	# make db-add REPO=vuls-data-extracted-attack
	# make db-add REPO=vuls-data-extracted-capec
	# make db-add REPO=vuls-data-extracted-cwe
	# make db-add REPO=vuls-data-extracted-exploit-exploitdb
	# make db-add REPO=vuls-data-extracted-exploit-github
	# make db-add REPO=vuls-data-extracted-exploit-inthewild
	# make db-add REPO=vuls-data-extracted-exploit-trickest
	# make db-add REPO=vuls-data-extracted-jvn-feed-detail
	# make db-add REPO=vuls-data-extracted-jvn-feed-product
	# make db-add REPO=vuls-data-extracted-jvn-feed-rss
	# make db-add REPO=vuls-data-extracted-kev
	# make db-add REPO=vuls-data-extracted-mitre-cvrf
	# make db-add REPO=vuls-data-extracted-mitre-v4
	# make db-add REPO=vuls-data-extracted-mitre-v5
	# make db-add REPO=vuls-data-extracted-msf
	# make db-add REPO=vuls-data-extracted-nvd-feed-cve
	# make db-add REPO=vuls-data-extracted-nvd-feed-cpe 
	# make db-add REPO=vuls-data-extracted-nvd-feed-cpematch
	# make db-add REPO=vuls-data-extracted-snort

.PHONY: db-add
db-add: 
	git clone https://github.com/vulsio/${REPO}.git
	cat ${REPO}/datasource.json | jq --arg hash $(git -C ${REPO} rev-parse HEAD) '.extracted.commit |= $hash' > tmp 
	mv tmp ${REPO}/datasource.json
	vuls db add ${REPO}
	rm -rf ${REPO}