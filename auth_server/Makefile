.PHONY:run run-server build-linux build package stop stop-server docker-push generate-code
MAJOR_VERSION=1
MINOR_VERSION=0
UPDATE_VERSION=1
DIST_ROOT=dist
BUILD_NAME=auth_server

VERSION_TAG=$(MAJOR_VERSION).$(MINOR_VERSION).$(UPDATE_VERSION)
DIST_PATH=$(DIST_ROOT)/auth_server
# Docker specific
DOCKER_NAME=auth_server
BUILD_TAG_LATEST=latest
BUILD_TAG=release-$(VERSION_TAG)
DOCKER_IMAGE=sqilab/$(DOCKER_NAME)
# Go params
GO=go
BUILDER_GOOS_GOARCH="$(shell $(GO) env GOOS)_$(shell $(GO) env GOARCH)"

GOFLAGS ?= $(GOFLAGS:) -a -installsuffix cgo
ENV_FLAGS=ENV_TYPE='dev'

run-server:
	@echo Running web server for development
	#mkdir -p $(BUILD_WEBAPP_DIR)/dist/files
	$(ENV_FLAGS) $(GO) run $(GOFLAGS) ./main.go &
generate-code:
	go generate github.com/cesanta/docker_auth/auth_server
run:run-server
build: build-linux
build-linux:generate-code
	@echo Generate code
	@echo Check code
	env GO111MODULE=on go vet
	@echo Build Linux amd64
	env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GO111MODULE=on $(GO) build $(GOFLAGS) -o $(BUILD_NAME) main.go version.go

	@echo Delete version file
	rm version.go

build-image:
	@echo Building docker image
	build-linux
	cd $(DIST_PATH); @docker build -t $(DOCKER_IMAGE):$(BUILD_TAG) .; docker tag $(DOCKER_IMAGE):$(BUILD_TAG_LATEST)

package: build
	@ echo Packaging system

	rm -Rf $(DIST_ROOT)

	mkdir -p $(DIST_PATH)/bin

	@ echo Copy templates files
	cp -RL templates $(DIST_PATH)

	@ echo Copy GO build file to bin
	mv $(BUILD_NAME) $(DIST_PATH)/bin

	@echo Build docker
	cp Dockerfile $(DIST_PATH)
	cd $(DIST_PATH); docker build -t $(DOCKER_IMAGE):$(BUILD_TAG) .; docker tag $(DOCKER_IMAGE):$(BUILD_TAG) $(DOCKER_IMAGE):$(BUILD_TAG_LATEST)

stop-server:
	@for PID in $$(ps -ef | grep "[g]o run" | awk '{ print $$2 }'); do \
		echo stopping go $$PID; \
		kill $$PID; \
		done
	@for PID in $$(ps -ef | grep "[g]o-build" | awk '{ print $$2 }'); do \
		echo stopping $$PID; \
		kill $$PID; \
	done
stop: stop-server
