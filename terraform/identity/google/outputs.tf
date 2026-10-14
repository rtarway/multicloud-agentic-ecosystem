output "dataset_grants" {
  description = "Dataset-level BigQuery grants managed by this root"
  value       = { for k, g in local.dataset_grants : k => "${g.member} -> ${g.role} on ${g.dataset}" }
}

output "job_users" {
  description = "Principals granted roles/bigquery.jobUser on the project"
  value       = values(local.query_users)
}
