SHELL = /usr/bin/env bash
DOCKER ?= docker
GO ?= go

CLANG ?= $$(which clang)
LLVM_VERSION = 15.0.7

IMAGE_REPO = ghcr.io/vietanhduong
LLVM_IMAGE = $(IMAGE_REPO)/wbpf-llvm
COMPILER_IMAGE = $(IMAGE_REPO)/wbpf-compiler

CURRENT_SHORT_COMMIT = $$(git rev-parse --short HEAD)

.PHONY: build-examples
build-examples:
	make -C examples CC=$(CLANG) BUILD_BPF=1 build-all

.PHONY: test
test:
	sudo TEST_CC=$(CLANG) $(GO) test ./... -v -count=1

## DOCKER
.PHONY: push-llvm
push-llvm: build-llvm
	$(DOCKER) push $(LLVM_IMAGE):$(LLVM_VERSION)

.PHONY: build-llvm
build-llvm:
	$(DOCKER) buildx build ./docker/llvm \
		--build-arg LLVM_VERSION=$(LLVM_VERSION) \
		-t $(LLVM_IMAGE):$(LLVM_VERSION)
	
.PHONY: push-compiler
push-compiler: build-compiler
	$(DOCKER) push $(COMPILER_IMAGE):$(CURRENT_SHORT_COMMIT)

.PHONY: build-compiler
build-compiler:
	$(DOCKER) buildx build . -f ./docker/compiler/Dockerfile \
		-t $(COMPILER_IMAGE):$(CURRENT_SHORT_COMMIT)
