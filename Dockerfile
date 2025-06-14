FROM --platform=$BUILDPLATFORM golang:alpine AS builder
WORKDIR /src
ENV CGO_ENABLED=0

COPY go.* .
RUN go mod download
COPY *.go .

ARG TARGETARCH
ARG TARGETOS

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /go/bin/goflarecar

FROM scratch AS bin
LABEL org.opencontainers.image.source=https://github.com/parente/goflarecar
COPY --from=builder /go/bin/goflarecar /go/bin/goflarecar
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/go/bin/goflarecar"]