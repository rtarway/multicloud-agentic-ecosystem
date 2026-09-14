# Keycloak Realm Import ConfigMap
resource "kubernetes_config_map" "keycloak_realm_config" {
  metadata {
    name      = "keycloak-realm-config"
    namespace = kubernetes_namespace.keycloak.metadata[0].name
  }

  data = {
    "azure-wif-realm.json" = file("${path.module}/../k8s/keycloak/keycloak-realm-configmap.yaml") != "" ? yamldecode(file("${path.module}/../k8s/keycloak/keycloak-realm-configmap.yaml"))["data"]["azure-wif-realm.json"] : ""
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
          image = "quay.io/keycloak/keycloak:24.0.4"
          args  = ["start-dev", "--import-realm", "--features=token-exchange,admin-fine-grained-authz"]

          env {
            name  = "KEYCLOAK_ADMIN"
            value = "admin"
          }
          env {
            name  = "KEYCLOAK_ADMIN_PASSWORD"
            value = "admin"
          }
          env {
            name  = "KC_HTTP_ENABLED"
            value = "true"
          }
          env {
            name  = "KC_HOSTNAME_STRICT"
            value = "false"
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
            name       = "realm-import"
            mount_path = "/opt/keycloak/data/import"
            read_only  = true
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
              path = "/realms/azure-wif-realm"
              port = 8080
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }
        }

        volume {
          name = "realm-import"
          config_map {
            name = kubernetes_config_map.keycloak_realm_config.metadata[0].name
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
