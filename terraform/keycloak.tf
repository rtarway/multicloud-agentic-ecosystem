# Keycloak bootstrap admin credentials. The password comes from TF_VAR_keycloak_admin_password (no default) and is
# kept in a Kubernetes Secret rather than a plain env value. The realm, users and clients are NOT imported from a
# file any more: they are provisioned from identity/users.yaml by terraform/identity/keycloak.
resource "kubernetes_secret" "keycloak_admin" {
  metadata {
    name      = "keycloak-admin"
    namespace = kubernetes_namespace.keycloak.metadata[0].name
  }

  data = {
    username = var.keycloak_admin_user
    password = var.keycloak_admin_password
  }
}

# Keycloak ServiceAccount
resource "kubernetes_service_account" "keycloak_sa" {
  metadata {
    name      = "keycloak-sa"
    namespace = kubernetes_namespace.keycloak.metadata[0].name
  }
}

# Keycloak Deployment with auto-import
resource "kubernetes_deployment" "keycloak" {
  metadata {
    name      = "keycloak"
    namespace = kubernetes_namespace.keycloak.metadata[0].name
    labels = {
      app = "keycloak"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "keycloak"
      }
    }

    template {
      metadata {
        labels = {
          app = "keycloak"
        }
      }

      spec {
        service_account_name = kubernetes_service_account.keycloak_sa.metadata[0].name

        container {
          name  = "keycloak"
          image = var.keycloak_image
          args  = ["start-dev"]

          env {
            name = "KEYCLOAK_ADMIN"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.keycloak_admin.metadata[0].name
                key  = "username"
              }
            }
          }
          env {
            name = "KEYCLOAK_ADMIN_PASSWORD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.keycloak_admin.metadata[0].name
                key  = "password"
              }
            }
          }
          env {
            name  = "KC_HTTP_ENABLED"
            value = "true"
          }
          # A fixed public URL makes the `iss` claim identical no matter how Keycloak is reached (browser via port-forward,
          # services via the cluster DNS name). Back-channel endpoints (token, JWKS) stay reachable on the internal URL.
          env {
            name  = "KC_HOSTNAME"
            value = var.keycloak_public_url
          }
          env {
            name  = "KC_HOSTNAME_BACKCHANNEL_DYNAMIC"
            value = "true"
          }
          env {
            name  = "JAVA_OPTS_APPEND"
            value = "-Xms256m -Xmx512m -XX:MaxMetaspaceSize=192m"
          }

          port {
            name           = "http"
            container_port = 8080
          }

          volume_mount {
            name       = "keycloak-data"
            mount_path = "/opt/keycloak/data/h2"
          }

          resources {
            requests = {
              cpu    = "250m"
              memory = "512Mi"
            }
            limits = {
              cpu    = "1000m"
              memory = "1536Mi"
            }
          }

          readiness_probe {
            http_get {
              path = "/realms/master"
              port = 8080
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }
        }

        volume {
          name = "keycloak-data"
          empty_dir {}
        }
      }
    }
  }
}

# Keycloak Service
resource "kubernetes_service" "keycloak_service" {
  metadata {
    name      = "keycloak-service"
    namespace = kubernetes_namespace.keycloak.metadata[0].name
  }

  spec {
    type = "ClusterIP"

    selector = {
      app = "keycloak"
    }

    port {
      name        = "http"
      port        = 8080
      target_port = 8080
    }
  }
}
