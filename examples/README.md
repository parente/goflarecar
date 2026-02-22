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
- `just`, `kubectl`, `kustomize`, and `terraform` CLI tools
- A (free) Cloudflare account
- A domain name configured in that Cloudflare account
- A Cloudflare account-level access token with the following permissions:
  - Account -> Access: Identity Providers -> Edit
  - Account -> Access: Apps and Policies -> Edit
  - Account -> Access: Organizations -> Read
  - Account -> Cloudflare Tunnel -> Edit
  - Zone -> DNS -> Edit limited to the domain name / zone you plan to use

## Configuration

Start by initializing the local Terraform workspace.

```bash
just terraform init
```

Apply the Terraform, either providing values for all of the variables in `variables.tf` when
prompted, or through any other means supported by the `terraform` CLI (e.g., `.tfvars` file).

```bash
just terraform apply
```

Retrieve the Terraform outputs.

```bash
# Audience tag generated for the Cloudflare Access application
export CF_AUDIENCE_TAG=$(just terraform output cf_audience_tag | tr -d \")
# Issuer URL for account hosting the Cloudflare Access application
export CF_ISSUER_URL=$(just terraform output cf_issuer_url | tr -d \")
# Cloudflare tunnel authentication token
export CF_TUNNEL_TOKEN=$(just terraform output cf_tunnel_token | tr -d \")
```

Kustomize and apply the Kubernetes manifests to the active cluster and namespace on localhost, using
the environment variable values.

```bash
just kustomize | kubectl apply -f -
```

Start the tunnel between Cloudflare and localhost.

```bash
just tunnel
```

Visit `https://<your-app-domain>` in your browser. You should be prompted to enter your email
address to receive 6-digit code. Enter that code and you should see the echo server JSON response.
Enter any other email or an incorrect code and you shouldn't gain access to the echo server app.

Visit `https://<your-aoo-domain>/websocket` in a browser for an interactive WebSocket demo. After
Cloudflare authentication, the page connects to the same `/websocket` endpoint via WebSocket,
displays your Cloudflare identity, and lets you send and receive echo messages.

### For 1Password users

As a 1Password user, you can avoid putting configuration values on disk or re-entering them every
time you start a shell.

Start by creating a secure note named `development` in a `goflarecar` 1Password vault. Create and
populate fields in the secure note for the `TF_VAR_*` variables in `op.env` to reference. For
example, put the Cloudflare API token from the prerequisites into a `CF_API_TOKEN` password field in
the note. Repeat for the rest.

With those fields in place, apply the Terraform.

```bash
just terraform init
op run --env-file=op.env --no-masking -- just terraform apply
```

Update the secure note with the outputs from Terraform.

```bash
op item edit 'development' "generated.CF_AUDIENCE_TAG=$(just terraform output cf_audience_tag | tr -d \")" --vault goflarecar
op item edit 'development' "generated.CF_ISSUER_URL=$(just terraform output cf_issuer_url | tr -d \")" --vault goflarecar
op item edit 'development' "generated.CF_TUNNEL_TOKEN=$(just terraform output cf_tunnel_token | tr -d \")" --vault goflarecar
```

Kustomize and apply the Kubernetes manifests to the active cluster and namespace on localhost, using
values found in the 1Password item.

```bash
op run --env-file=op.env --no-masking -- just kustomize | kubectl apply -f -
```

Start the tunnel between Cloudflare and localhost.

```bash
op run --env-file=op.env --no-masking -- just tunnel
```
