SHELL = /usr/bin/env bash


CC ?= clang
EXAMPLES = $(shell find . -mindepth 1 -maxdepth 1 -type d ! -name "headers" -exec basename {} \;)

BUILD_TARGET_PREFIX = build-
BUILD_TARGETS = $(addprefix $(BUILD_TARGET_PREFIX),$(EXAMPLES))

UNAME_P = $(shell uname -p)
ifneq ($(filter arm%,$(UNAME_P)),)
	TARGET_ARCH = arm64
endif

ifeq ($(TARGET_ARCH),)
	TARGET_ARCH = x86
endif

.PHONY: build-all
build-all: $(BUILD_TARGETS)

.PHONY: $(BUILD_TARGETS)
$(BUILD_TARGETS):
	$(eval TARGET = $(@:$(BUILD_TARGET_PREFIX)%=%))	
ifeq ($(BUILD_BPF),1)
	$(CC) -g -O2 \
		-Wall -Werror -fpie -Wno-unused-variable -Wno-unused-function \
		-target bpf \
		-c ./$(TARGET)/$(TARGET).bpf.c \
		-o ./$(TARGET)/$(TARGET).bpf.o \
		-D__TARGET_ARCH_$(TARGET_ARCH) \
		-mcpu=v1 \
		-I ./headers/vmlinux \
		-I ./headers/libbpf
endif

	if [ -n "$$(find ./$(TARGET) -type f -name "*.go")" ]; then \
		CGO_ENABLED=0 go build -v -o ./$(TARGET)/$(TARGET) ./$(TARGET); \
	fi;
