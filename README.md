# goflarecar

Sidecar proxy for [validating Cloudflare Access
JWTs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/).
Written in Go.

## Why does this exist?

This project exists because I wanted the following:

1. To see how well Gemini circa mid-2025 could do bootstrapping this project on its own
2. To learn more about wiring up Cloudflare tunnels and applications in Terraform
3. A drop-in authenticating proxy sidecar for low-traffic web apps on Kubernetes
4. A simple way to pass validated auth claims from proxy to origin server

If you're looking for alternative, more flexible and robust solutions, consider instead:

- A [`cloudflared` deployment on your Kubernetes
  cluster](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/deployment-guides/kubernetes/)
- A Cloudflare [gateway](https://github.com/pl4nty/cloudflare-kubernetes-gateway) or [ingress
  controller ](https://github.com/STRRL/cloudflare-tunnel-ingress-controller) controller
  implementation

## Using it

Using this proxy requires the following steps:

1. Configure a [Cloudflare One identity provider
   (IdP)](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/) and
   both Cloudflare Access
   [application](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/)
   and [policy](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/) using
   it.
2. Run an instance of the proxy with the `CF_ISSUER_URL`, `CF_AUDIENCE_TAG`, and `UPSTREAM_APP_URL`
   minimally set.
3. Direct all traffic from your Cloudflare Access application domain to the proxy instance and
   ensure no traffic can reach your origin server directly.

See [examples/README](./examples/README.md) for a sample of how to run the proxy as an
authenticating sidecar container in k8s.

## Features and limitations

The proxy has the following features and limitations:

- [x] HTTP support
- [x] Websocket support
- [x] Cloudflare JWT validation (for authn at the proxy layer)
- [x] Cloudflare signing-certificate refresh
- [x] Injection of validated claim headers
- [ ] Cloudflare identity support (for authz at the proxy layer)
- [ ] TLS termination

## Configuration

The proxy supports configuration via the following environment variables:

| Name                   | Description                                                                                                                     |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| CF_ISSUER_URL          | Cloudflare generated URL of the form https://<something>.cloudflareaccess.com associated with your account                      |
| CF_AUDIENCE_TAG        | Cloudflare generated audience tag associated with. your Cloudflare Access application                                           |
| UPSTREAM_APP_URL_ENV   | HTTP URL of the origin server                                                                                                   |
| PROXY_LISTEN_ADDR_ENV  | Interface and port where the proxy server listens for connections (default: `:8080`)                                            |
| PROXY_PASS_JSON_CLAIMS | Set to `yes`, `true`, or `1` to inject the validated JSON claims into a request header for the origin server (default: `false`) |

## Injected headers

The proxy injects the following HTTP headers into requests forwarded to the origin server:

| Header                         | Description                                                                      |
| ------------------------------ | -------------------------------------------------------------------------------- |
| X-Authenticated-Claims-Issuer  | The validated JWT issuer, which should match the configured `CF_ISSUER_URL`      |
| X-Authenticated-Claims-Subject | The validated JWT subject, an IdP-dependent unique ID for the authenticated user |
| X-Authenticated-Claims-JSON    | The validate JWT JSON claims if `PROXY_PASS_JSON_CLAIMS` is enabled              |

## Maintaining this project

To make a release, push an annotated `vX.Y.Z` tag. Then create a GitHub release for that tag.

```bash
git switch main
git pull origin main
git tag -a 'v1.0.0'
git push origin v1.0.0
gh release create v1.0.0 --verify-tag --generate-notes --draft
gh release view v1.0.0
gh release create v1.0.0 --draft=false
```
