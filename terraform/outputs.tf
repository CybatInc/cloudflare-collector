output "worker_name" {
  description = "The name of the deployed Cloudflare Worker."
  value       = cloudflare_worker_script.cybat_collector.name
}

output "attached_routes" {
  description = "The routes bound to the Cybat Intelligence Engine Edge Collector."
  value       = [for r in cloudflare_worker_route.routes : r.pattern]
}
