export IMAGE_LATEST := "latest"
export IMAGE_SHA := `git rev-parse HEAD | cut -c-12`

CF_ISSUER_URL := env_var_or_default("CF_ISSUER_URL", "https://example.cloudflareaccess.com")
CF_AUDIENCE_TAG := env_var_or_default("CF_AUDIENCE_TAG", "example-audience")
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
	gofmt -s -w .
	golangci-lint run

	pushd examples/echo_server
	gofmt -s -w .
	golangci-lint run
	popd

kustomize:
	#!/bin/bash
	set -euxo pipefail
	cd examples/echo_sidecar

	cat <<EOF >.env
	CF_ISSUER_URL={{CF_ISSUER_URL}}
	CF_AUDIENCE_TAG={{CF_AUDIENCE_TAG}}
	EOF

	cat <<EOF >.ingress.yaml
	- op: replace
	  path: /spec/rules/0/host
	  value: {{INGRESS_HOST}}
	- op: replace
	  path: /spec/tls/0/hosts/0
	  value: {{INGRESS_HOST}}
	EOF

	kustomize build .

# Build and run the Go application
run:
	go run main.go