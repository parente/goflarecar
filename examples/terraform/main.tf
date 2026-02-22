terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

provider "cloudflare" {}

# Create an identity provider based on emailed one-time PINs
resource "cloudflare_zero_trust_access_identity_provider" "email_pin" {
  name       = "goflarecar PIN IdP"
  type       = "onetimepin"
  config     = {}
  account_id = var.cf_account_id
}

# Create a Cloudflare tunnel
resource "cloudflare_zero_trust_tunnel_cloudflared" "goflarecar" {
  name       = "goflarecar development tunnel"
  config_src = "cloudflare"
  account_id = var.cf_account_id
}

# Create a route from Cloudflare through the tunnel to the sidecar proxy on localhost
resource "cloudflare_zero_trust_tunnel_cloudflared_config" "goflarecar" {
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.goflarecar.id
  account_id = var.cf_account_id

  config = {
    ingress = [
      {
        hostname = var.cf_app_domain
        service  = "http://localhost:8080"
      },
      {
        service = "http_status:404"
      }
    ]
  }
}

# Create a public DNS record for the tunnel
resource "cloudflare_dns_record" "goflarecar" {
  zone_id = var.cf_zone_id
  name    = var.cf_app_domain
  content = "${cloudflare_zero_trust_tunnel_cloudflared.goflarecar.id}.cfargotunnel.com"
  type    = "CNAME"
  ttl     = 1
  proxied = true
}

# Create an policy allowing access by an email address authenticated through the IdP
resource "cloudflare_zero_trust_access_policy" "email_pin" {
  account_id = var.cf_account_id
  name       = "Allow email addresses"
  decision   = "allow"
  include = [
    {
      email = {
        email = var.cf_allowed_email
      }
    }
  ]
}

# Create a Cloudflare Access application with the policy attached
resource "cloudflare_zero_trust_access_application" "goflarecar" {
  account_id = var.cf_account_id
  type       = "self_hosted"
  name       = "Access application for ${var.cf_app_domain}"
  domain     = var.cf_app_domain
  policies = [
    {
      id         = cloudflare_zero_trust_access_policy.email_pin.id
      precedence = 1
    }
  ]
}
