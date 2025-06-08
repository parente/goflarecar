variable "IMAGE_REPO" {
  default = "ghcr.io/parente/goflarecar"
}
variable "IMAGE_SHA" {}
variable "IMAGE_TAG" {}

group "default" {
  targets = ["goflarecar", "echo-example"]
}

target "goflarecar" {
  platforms = ["linux/amd64", "linux/arm64"]
  tags = [
    "${IMAGE_REPO}:${IMAGE_SHA}",
    "${IMAGE_REPO}:${IMAGE_TAG}",
    equal("${IMAGE_TAG}", "main") ? "${IMAGE_REPO}:latest" : "",
  ]
}

target "echo-example" {
  context    = "./examples/echo_server"
  dockerfile = "Dockerfile"
  platforms  = ["linux/amd64", "linux/arm64"]
  tags = [
    "${IMAGE_REPO}-echo:${IMAGE_SHA}",
    "${IMAGE_REPO}-echo:${IMAGE_TAG}",
    equal("${IMAGE_TAG}", "main") ? "${IMAGE_REPO}:latest" : "",
  ]
}
