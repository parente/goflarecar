export IMAGE_TAG := env_var_or_default("IMAGE_TAG", "latest")
export IMAGE_SHA := `git rev-parse HEAD | cut -c-12`

# List targets (local)
help:
	@just --list --unsorted

# Bake a container image
bake:
	docker buildx bake --load -f docker-bake.hcl

# Format and lint Go code
check:
	gofmt -s -w .
	golangci-lint run

# Build and run the Go application
run:
	go run main.go