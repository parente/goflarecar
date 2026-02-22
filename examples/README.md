This folder includes resources for deploying a web application to a local Kubernetes (k8s) cluster
running on your laptop and protecting it with Cloudflare Access authentication.

## Components

- `echo_server/` - A web server that echoes HTTP requests and Websocket messages back to the caller
- `echo_sidecar/` - Kubernetes manifests for deploying the echo server to a cluster fronted by the
  proxy as a sidecar container and a load balancer service
- `terraform/` - Terraform for configuring Cloudflare IdP, application, and policy protecting the
  echo server with email PIN based authentication

## Prerequisites

- A small k8s cluster (e.g., [one provisioned by Docker
  Desktop](https://docs.docker.com/desktop/use-desktop/kubernetes/))
- A (free) Cloudflare account
- A domain name configured in that Cloudflare account
- A Cloudflare account-level access token with the following permissions:
  - TODO

##
