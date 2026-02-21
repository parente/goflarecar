export IMAGE_LATEST := "latest"
export IMAGE_SHA := `git rev-parse HEAD | cut -c-12`

CF_ISSUER_URL := env_var_or_default("CF_ISSUER_URL", "https://example.cloudflareaccess.com")
CF_AUDIENCE_TAG := env_var_or_default("CF_AUDIENCE_TAG", "example-audience")
CF_TUNNEL_TOKEN := env_var_or_default("CF_TUNNEL_TOKEN", "example-tunnel-token")
INGRESS_HOST := env_var_or_default("INGRESS_HOST", "echo-sidecar.example.com")

# List targets (local)
help:
	@just --list --unsorted

# Bake a container image
bake:
	docker buildx bake --load -f docker-bake.hcl

# Format and lint Go code
check:
	#!/bin/bash
	set -euxo pipefail

	gofmt -s -w .
	golangci-lint run

	pushd examples/echo_server
	gofmt -s -w .
	golangci-lint run
	popd

# Kustomize example cluster resources
kustomize:
	#!/bin/bash
	set -euxo pipefail
	cd examples/echo_sidecar

	cat <<EOF >.configmap.env
	CF_ISSUER_URL={{CF_ISSUER_URL}}
	CF_AUDIENCE_TAG={{CF_AUDIENCE_TAG}}
	EOF

	kustomize build .

# Build and run the Go application
run:
	go run main.go

# Run a cloudflared tunnel
tunnel:
	cloudflared tunnel run --token {{CF_TUNNEL_TOKEN}}