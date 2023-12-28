SHELL := /usr/bin/env bash
GO ?= go
CLANG ?= $$(which clang)

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

