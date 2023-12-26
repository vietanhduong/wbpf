#!/bin/bash

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

LLVM_SRC=/src/llvm

mkdir -p $LLVM_SRC &&
  curl -sSL "https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-${LLVM_VERSION}.tar.gz" |
  tar -xzf - --strip-components=1 -C $LLVM_SRC
