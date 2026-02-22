variable "cf_account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "cf_zone_id" {
  description = "Cloudflare zone ID for the application domain"
  type        = string
}

variable "cf_app_domain" {
  description = "Cloudflare application domain name"
  type        = string
}

variable "cf_allowed_email" {
  description = "Email address allowed to access the application"
  type        = string
}
