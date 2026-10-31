terraform {
  required_version = ">= 1.5.0"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

resource "cloudflare_worker_script" "cybat_collector" {
  account_id         = var.cloudflare_account_id
  name               = var.worker_name
  content            = file("${path.module}/../src/index.js")
  module             = true
  compatibility_date = "2024-10-30"

  plain_text_binding {
    name = "CYBAT_INGESTION_URL"
    text = var.cybat_ingestion_url
  }

  plain_text_binding {
    name = "CYBAT_MAX_BODY_BYTES"
    text = tostring(var.cybat_max_body_bytes)
  }

  secret_text_binding {
    name = "CYBAT_API_KEY"
    text = var.cybat_api_key
  }
}

resource "cloudflare_worker_route" "routes" {
  for_each    = toset(var.routes)
  zone_id     = var.cloudflare_zone_id
  pattern     = each.value
  script_name = cloudflare_worker_script.cybat_collector.name
}
