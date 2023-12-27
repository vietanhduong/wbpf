FROM --platform=linux/amd64 ubuntu:22.04 as builder

ARG LLVM_VERSION=15.0.7
ENV LLVM_VERSION=${LLVM_VERSION}

COPY *.sh /

RUN  /install_deps.sh 
RUN  /download_llvm.sh 
RUN  /build_llvm_native.sh 
RUN  /build_llvm_cross_aarch64.sh

FROM ubuntu:22.04 as rootfs
ARG TARGETPLATFORM
COPY --from=builder /out/${TARGETPLATFORM}/bin /usr/local/bin

FROM scratch
LABEL org.opencontainers.image.source=https://github.com/vietanhduong/wbpf
LABEL maintainer="vietanhs0817@gmail.com"
# Squash image
COPY --from=rootfs / /
