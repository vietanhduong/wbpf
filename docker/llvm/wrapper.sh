#!/bin/bash

BINARY=""
case "$(basename $0)" in
clang)
  BINARY=clang
  ;;
llc)
  BINARY=llc
  ;;
llvm-objcopy)
  BINARY=llvm-objcopy
  ;;
*)
  echo "Unsupported binary: $(basename $0)"
  exit 1
  ;;
esac

ARCH=$(uname -m)

case $ARCH in
i386 | x86_64)
  BINARY="$BINARY-amd64"
  ;;
aarch64)
  BINARY="$BINARY-arm64"
  ;;
*)
  echo "Unsupported architecture: $ARCH"
  exit 1
  ;;
esac

exec "$BINARY" "$@"
