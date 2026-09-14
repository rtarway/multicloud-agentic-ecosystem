output "workload_identity_pool_name" {
  description = "Fully qualified Google Cloud Workload Identity Pool name"
  value       = google_iam_workload_identity_pool.agent_pool.name
}

output "workload_identity_provider_name" {
  description = "Fully qualified Google Cloud Workload Identity Provider name"
  value       = google_iam_workload_identity_pool_provider.spire_provider.name
}

output "bigquery_analytics_dataset_id" {
  description = "BigQuery dataset ID for analytics data"
  value       = google_bigquery_dataset.analytics_data.dataset_id
}

output "bigquery_audit_dataset_id" {
  description = "BigQuery dataset ID for audit logs"
  value       = google_bigquery_dataset.audit_logs.dataset_id
}

output "service_account_email" {
  description = "Service Account email for BigQuery MCP server"
  value       = google_service_account.gcp_mcp_sa.email
}

