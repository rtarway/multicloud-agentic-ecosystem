# Configure Istio Service Mesh to use SPIRE-issued X.509 SVIDs for mTLS
# Citadel CA is completely disabled, delegating all workload certificate issuance to SPIRE.

resource "helm_release" "istio_base" {
  name       = "istio-base"
  repository = "https://istio-release.storage.googleapis.com/charts"
  chart      = "base"
  version    = "1.22.0"
  namespace  = kubernetes_namespace.istio_system.metadata[0].name
}

resource "helm_release" "istiod" {
  name       = "istiod"
  repository = "https://istio-release.storage.googleapis.com/charts"
  chart      = "istiod"
  version    = "1.22.0"
  namespace  = kubernetes_namespace.istio_system.metadata[0].name

  depends_on = [helm_release.istio_base]

  values = [
    yamlencode({
      global = {
        imagePullPolicy = "IfNotPresent"
        proxy_init = {
          image = "istio/proxyv2:1.22.0-nft"
        }
      }
      pilot = {
        env = {
          # Turn off Citadel CA in Istio completely
          PILOT_ENABLE_CA_SERVER = "false"
        }
      }
      meshConfig = {
        trustDomain = var.spire_trust_domain
        # Mount SPIRE Agent Workload API socket directly into Istio Envoy sidecars for mTLS X.509 SVIDs
        defaultConfig = {
          userVolume      = "{\"name\":\"spiffe-workload-api\",\"csi\":{\"driver\":\"csi.spiffe.io\",\"readOnly\":true}}"
          userVolumeMount = "{\"name\":\"spiffe-workload-api\",\"mountPath\":\"/run/spire/sockets\",\"readOnly\":true}"
        }
      }
    })
  ]
}
