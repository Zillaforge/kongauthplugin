OWNER ?= Zillaforge
PROJECT ?= KongAuthPlugin
GOVERSION ?= 1.22.4
PREVERSION ?= 2.0.3
OS ?= ubuntu
ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
VERSION ?= $(shell cat VERSION)
PWD := $(shell pwd)
PLUGIN_NAME ?= kong-auth-plugin
SYSTEM_REGISTRY ?= asuscloud:31350
# GO_PROXY ?= "https://proxy.golang.org,http://proxy.pegasus-cloud.com:8078"

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
	@docker run --name build-env -v $(PWD):/home/kongauthplugin -w /home/kongauthplugin $(OWNER)/golang:$(GOVERSION)-$(OS)-$(ARCH) make go-build
	@docker rm -f build-env

# Release docker image
#  Build binary and save it in docker image
#  ex: make release-image OS=ubuntu
.PHONY: release-image
release-image:
	@make build
	@echo "Build Container Image"
	@docker rmi -f $(OWNER)/$(PLUGIN_NAME):$(VERSION)
	@docker build --platform linux/${ARCH} -t $(OWNER)/$(PLUGIN_NAME):$(VERSION) .
	@mkdir -p tmp/container
	@docker save $(OWNER)/$(PLUGIN_NAME):$(VERSION) > tmp/container/$(PLUGIN_NAME)_$(VERSION).image.tar

.PHONY: push-image
push-image:
	@echo "Check Image $(OWNER)/$(PLUGIN_NAME):$(VERSION)"
	@docker image inspect $(OWNER)/$(PLUGIN_NAME):$(VERSION) --format="image existed"
	@echo "Push Image"
	@docker logout
	@docker login -u $(OWNER) --password-stdin <<< "<DOCKER HUB KEY>"
	@docker image push $(OWNER)/$(PLUGIN_NAME):$(VERSION)
	@docker logout

.PHONY: start-dev-env
start-dev-env:
	@make start-dev-persistent
	@make start-dev-system
	@make start-dev-service

.PHONY: start-dev-service
start-dev-service: docker-compose/service/docker-compose.*.yaml
	@for f in $^; do ARCH=$(ARCH) COMPOSE_IGNORE_ORPHANS=True docker-compose -f $${f} -p "pegasus-service" up -d --no-recreate || true ; done

.PHONY: start-dev-system
start-dev-system: docker-compose/system/docker-compose.*.yaml
	@for f in $^; do COMPOSE_IGNORE_ORPHANS=True docker-compose -f $${f} -p "pegasus-system" up -d --no-recreate || true ; done

.PHONY: start-dev-persistent
start-dev-persistent: docker-compose/persistent/docker-compose.*.yaml
	@for f in $^; do COMPOSE_IGNORE_ORPHANS=True docker-compose -f $${f} -p "pegasus-system" up -d --no-recreate --no-start || true ; done

.PHONY: stop-dev-env # Stop and Remove current service only
stop-dev-env:
	COMPOSE_IGNORE_ORPHANS=True docker-compose -f docker-compose/service/docker-compose.${ABBR}.yaml -p "pegasus-service" down
	
.PHONY: stop-dev-all # Stop and Remove all dependency
stop-dev-all:
	@make stop-dev-service
	@make stop-dev-system

.PHONY: purge-dev-all # Stop and Remove all dependency include persistent network and volume
purge-dev-all:
	@make stop-dev-all
	@make clean-dev-persistent

.PHONY: stop-dev-service
stop-dev-service: docker-compose/service/docker-compose.*.yaml
	@for f in $^; do COMPOSE_IGNORE_ORPHANS=True docker-compose -f $${f} -p "pegasus-service" down -v; done

.PHONY: stop-dev-system
stop-dev-system: docker-compose/system/docker-compose.*.yaml
	@for f in $^; do COMPOSE_IGNORE_ORPHANS=True docker-compose -f $${f} -p "pegasus-system" down -v; done

.PHONY: clean-dev-persistent
clean-dev-persistent: docker-compose/persistent/docker-compose.*.yaml
	@for f in $^; do COMPOSE_IGNORE_ORPHANS=True docker-compose -f $${f} -p "pegasus-system" down -v; done
