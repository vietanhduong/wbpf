SHELL := /usr/bin/env bash

DOCKER ?= docker


LLVM_VERSION = 15.0.7

IMAGE_REPO = ghcr.io/vietanhduong
LLVM_IMAGE = $(IMAGE_REPO)/wbpf-llvm
COMPILER_IMAGE = $(IMAGE_REPO)/wbpf-compiler

PUSH ?= false
DOCKER_OUTPUT = "type=image"
ifeq ($(PUSH), true)
DOCKER_OUTPUT	= "type=registry,push=true"
endif

PLATFORMS = linux/amd64,linux/arm64
CURRENT_SHORT_COMMIT = $$(git rev-parse --short HEAD)

## DOCKER
.buildx_builder:
	docker buildx create --platform $(PLATFORMS) --buildkitd-flags '--debug' > $@ 

.PHONY: build-llvm
build-llvm: .buildx_builder
	$(DOCKER) buildx build ./docker/llvm \
		--build-arg LLVM_VERSION=$(LLVM_VERSION) \
		--platform=$(PLATFORMS) \
		--output=$(DOCKER_OUTPUT) \
		--builder="$( cat $<)" \
		--tag $(LLVM_IMAGE):$(LLVM_VERSION)
	

.PHONY: build-compiler
build-compiler: .buildx_builder
	$(DOCKER) buildx build . --file ./docker/compiler/Dockerfile \
		--platform=$(PLATFORMS) \
		--output=$(DOCKER_OUTPUT) \
		--builder="$( cat $<)" \
		--tag $(COMPILER_IMAGE):$(CURRENT_SHORT_COMMIT)
