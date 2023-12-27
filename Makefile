SHELL = /usr/bin/env bash
DOCKER ?= docker
GO ?= go
CLANG ?= $$(which clang)
PLATFORMS = linux/amd64,linux/arm64


LLVM_VERSION = 15.0.7

IMAGE_REPO = ghcr.io/vietanhduong
LLVM_IMAGE = $(IMAGE_REPO)/wbpf-llvm
COMPILER_IMAGE = $(IMAGE_REPO)/wbpf-compiler

CURRENT_SHORT_COMMIT = $$(git rev-parse --short HEAD)

PUSH ?= false
DOCKER_OUTPUT = "type=image"
ifeq ($(PUSH), true)
DOCKER_OUTPUT	= "type=registry,push=true"
endif

.PHONY: build-examples
build-examples:
	make -C examples CC=$(CLANG) BUILD_BPF=1 build-all

.PHONY: test
test:
ifndef CI
	sudo TEST_CC=$(CLANG) $(GO) test ./... -v -count=1
else
	TEST_CC=$(CLANG) $(GO) test ./... -v -count=1 -exec=sudo
endif

## DOCKER
buildx_builder:
	docker buildx create --platform $(PLATFORMS) --buildkitd-flags '--debug' --name $@

.PHONY: build-llvm
build-llvm: buildx_builder
	$(DOCKER) buildx build ./docker/llvm \
		--build-arg LLVM_VERSION=$(LLVM_VERSION) \
		--platform=$(PLATFORMS) \
		--output=$(DOCKER_OUTPUT) \
		--builder="$<" \
		--tag $(LLVM_IMAGE):$(LLVM_VERSION)
	

.PHONY: build-compiler
build-compiler: buildx_builder
	$(DOCKER) buildx build . --file ./docker/compiler/Dockerfile \
		--platform=$(PLATFORMS) \
		--output=$(DOCKER_OUTPUT) \
		--builder="$<" \
		--tag $(COMPILER_IMAGE):$(CURRENT_SHORT_COMMIT)
