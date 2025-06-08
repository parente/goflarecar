variable "IMAGE_REPO" {
  default = "ghcr.io/parente/goflarecar"
}
variable "IMAGE_SHA" {}
variable "IMAGE_TAG" {}
variable "IMAGE_LATEST" {}

group "default" {
  targets = ["goflarecar", "echo-example"]
}

target "goflarecar" {
  platforms = ["linux/amd64", "linux/arm64"]
  tags = [
    "${IMAGE_REPO}:${IMAGE_SHA}",
    equal("${IMAGE_TAG}", "") ? "" : "${IMAGE_REPO}:${IMAGE_TAG}",
    equal("${IMAGE_LATEST}", "latest") ? "${IMAGE_REPO}:latest" : "",
  ]
}

target "echo-example" {
  context    = "./examples/echo_server"
  dockerfile = "Dockerfile"
  platforms  = ["linux/amd64", "linux/arm64"]
  tags = [
    "${IMAGE_REPO}-echo:${IMAGE_SHA}",
    equal("${IMAGE_TAG}", "") ? "" : "${IMAGE_REPO}-echo:${IMAGE_TAG}",
    equal("${IMAGE_LATEST}", "latest") ? "${IMAGE_REPO}-echo:latest" : "",
  ]
}
