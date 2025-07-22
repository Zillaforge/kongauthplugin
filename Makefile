OWNER ?= ociscloud
PROJECT ?= KongAuthPlugin
GOVERSION ?= 1.22.4
PREVERSION ?= 2.0.2
OS ?= ubuntu
ARCH ?= amd64
VERSION ?= $(shell cat VERSION)
PWD := $(shell pwd)
IAMPATH := $(PWD)/../pegasusiam
PLUGIN_NAME ?= kong-auth-plugin
SYSTEM_REGISTRY ?= asuscloud:31350
GO_PROXY ?= "https://proxy.golang.org,http://proxy.pegasus-cloud.com:8078"

sed = sed
ifeq ("$(shell uname -s)", "Darwin")	# BSD sed, like MacOS
	sed += -i ''
else	# GNU sed, like LinuxOS
	sed += -i''
endif

.PHONY: set-version
set-version:
	@echo "Set Version"
	@$(sed) -e'/$(PREVERSION)/{s//$(VERSION)/;:b' -e'n;bb' -e\} $(PWD)/Makefile
	@$(sed) -e'/$(PREVERSION)/{s//$(VERSION)/;:b' -e'n;bb' -e\} $(PWD)/kong_auth_plugin.go

.PHONY: go-build
go-build:
	@echo "Build Binary"
	@make set-version
	@rm -rf build
	@mkdir -p build
	@go build -o=build/$(PLUGIN_NAME)

.PHONY: build
build:
	@docker run --name build-env -e GOPROXY=$(GO_PROXY) -e GOSUMDB="off" --network=host -v $(PWD):/home/kongauthplugin -v $(IAMPATH):/home/pegasusiam -w /home/kongauthplugin $(OWNER)/golang:$(GOVERSION)-$(OS)-$(ARCH) make go-build
	@docker rm -f build-env

# Release docker image
#  Build binary and save it in docker image
#  ex: make release-image OS=ubuntu
.PHONY: release-image
release-image:
	@make build
	@echo "Build Container Image"
	@docker rmi -f ociscloud/$(PLUGIN_NAME):$(VERSION)
	@docker build -t ociscloud/$(PLUGIN_NAME):$(VERSION) .
	@mkdir -p tmp/container
	@docker save ociscloud/$(PLUGIN_NAME):$(VERSION) > tmp/container/$(PLUGIN_NAME)_$(VERSION).image.tar

.PHONY: push-image
push-image:
	@echo "Check Image ociscloud/$(PLUGIN_NAME):$(VERSION)"
	@docker image inspect ociscloud/$(PLUGIN_NAME):$(VERSION) --format="image existed"
	@echo "Push Image"
	@docker logout
	@docker login -u ociscloud --password-stdin <<< "<DOCKER HUB KEY>"
	@docker image push ociscloud/$(PLUGIN_NAME):$(VERSION)
	@docker logout