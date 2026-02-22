data "cloudflare_zero_trust_tunnel_cloudflared_token" "goflarecar" {
  account_id = var.cf_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.goflarecar.id
}

output "cf_tunnel_token" {
  description = "Secret token for cloudflared to authenticate with the Cloudflare network"
  value       = data.cloudflare_zero_trust_tunnel_cloudflared_token.goflarecar.token
  sensitive   = true
}

output "cf_audience_tag" {
  description = "Cloudflare Access Audience tag for the application"
  value       = cloudflare_zero_trust_access_application.goflarecar.aud
  sensitive   = true
}
