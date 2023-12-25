FROM golang:1.21 as builder

WORKDIR /src

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o ./dist/compiler ./cmd/compiler

FROM ghcr.io/vietanhduong/wbpf-llvm:15.0.7

COPY --from=builder /src/dist/compiler /usr/local/bin
