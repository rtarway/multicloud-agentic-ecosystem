output "keycloak_service_url" {
  description = "Internal Keycloak service endpoint"
  value       = "http://keycloak-service.keycloak.svc.cluster.local:8080"
}

output "spire_trust_domain" {
  description = "SPIRE Trust Domain"
  value       = var.spire_trust_domain
}

output "spire_oidc_issuer" {
  description = "SPIRE OIDC Issuer endpoint"
  value       = var.spire_jwt_issuer
}
