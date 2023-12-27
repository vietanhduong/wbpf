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

if [[ -z "$TARGETARCH" ]]; then
  TARGETARCH=$(uname -m)
  case $TARGETARCH in
  i386 | x86_64)
    BINARY="$BINARY-amd64"
    ;;
  aarch64)
    BINARY="$BINARY-arm64"
    ;;
  *)
    echo "Unsupported architecture: $TARGETARCH"
    exit 1
    ;;
  esac
else
  # For CI or docker build while we can select the architecture
  BINARY="$BINARY-$TARGETARCH"
fi

exec "$BINARY" "$@"
