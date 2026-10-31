variable "cloudflare_account_id" {
  description = "The Cloudflare Account ID where the Worker will be deployed."
  type        = string
}

variable "cloudflare_zone_id" {
  description = "The Cloudflare Zone ID for the domain where routes will be attached."
  type        = string
}

variable "worker_name" {
  description = "The name of the Cloudflare Worker script."
  type        = string
  default     = "cybat-edge-collector"
}

variable "cybat_api_key" {
  description = "The Cybat live API key for your organization (secret)."
  type        = string
  sensitive   = true
}

variable "cybat_ingestion_url" {
  description = "Destination URL for Cybat telemetry ingestion."
  type        = string
  default     = "https://gcp-ingest.cybat.co"
}

variable "project_id" {
  description = "The project identifier reported to Cybat for analytics breakdown."
  type        = string
  default     = "cloudflare"
}

variable "cybat_max_body_bytes" {
  description = "Maximum body size in bytes to extract for state-changing requests (default: 65536)."
  type        = number
  default     = 65536
}

variable "routes" {
  description = "List of route patterns to attach the Cybat Intelligence Engine Edge Collector to (e.g., ['api.example.com/*'])."
  type        = list(string)
  default     = []
}
