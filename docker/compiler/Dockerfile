FROM --platform=${TARGETPLATFORM} golang:1.21 as builder

WORKDIR /src
COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -o ./dist/compiler ./cmd/compiler

FROM --platform=${TARGETPLATFORM} ghcr.io/vietanhduong/wbpf-llvm:15.0.7
COPY --from=builder /src/dist/compiler /usr/local/bin
