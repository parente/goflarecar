variable "cf_account_id" {
  description = "Cloudflare account ID. Visible in URL after signing into the Cloudflare dashboard (e.g., https://dash.cloudflare.com/1234567890abcdef1234567890abcdef/home)"
  type        = string
}

variable "cf_allowed_email" {
  description = "Email address allowed to access the application (i.e., your email address)"
  type        = string
}

variable "cf_api_token" {
  description = "Cloudflare API token with permissions to manage Access, DNS, and Tunnel resources"
  type        = string
  sensitive   = true
}

variable "cf_app_domain" {
  description = "Cloudflare application domain name (e.g., goflarecar.mydomain.com)"
  type        = string
}
