FROM ubuntu:22.04 as builder

ARG LLVM_VERSION=15.0.7
ENV LLVM_VERSION=${LLVM_VERSION}

COPY *.sh /

RUN /install_deps.sh && \
  /download_llvm.sh && \
  /build_llvm_native.sh && \
  /build_llvm_cross_aarch64.sh

FROM ubuntu:22.04 as rootfs

# Copy amd64 binary
COPY --from=builder /out/linux/amd64/bin/clang /usr/local/bin/clang-amd64
COPY --from=builder /out/linux/amd64/bin/llc /usr/local/bin/llc-amd64
COPY --from=builder /out/linux/amd64/bin/llvm-objcopy /usr/local/bin/llvm-objcopy-amd64

# Copy amd64 binary
COPY --from=builder /out/linux/arm64/bin/clang /usr/local/bin/clang-arm64
COPY --from=builder /out/linux/arm64/bin/llc /usr/local/bin/llc-arm64
COPY --from=builder /out/linux/arm64/bin/llvm-objcopy /usr/local/bin/llvm-objcopy-arm64

COPY wrapper.sh /usr/local/bin/clang
COPY wrapper.sh /usr/local/bin/llc
COPY wrapper.sh /usr/local/bin/llvm-objcopy

FROM scratch
LABEL org.opencontainers.image.source=https://github.com/vietanhduong/wbpf
LABEL maintainer="vietanhs0817@gmail.com"
COPY --from=rootfs / /
