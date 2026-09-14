# Deploy SPIRE CRDs
resource "helm_release" "spire_crds" {
  name             = "spire-crds"
  repository       = "https://spiffe.github.io/helm-charts-hardened/"
  chart            = "spire-crds"
  version          = "0.6.1"
  namespace        = kubernetes_namespace.spire.metadata[0].name
  create_namespace = false
}

# Deploy SPIRE Stack with SPIFFE CSI Driver enabled
resource "helm_release" "spire" {
  name             = "spire"
  repository       = "https://spiffe.github.io/helm-charts-hardened/"
  chart            = "spire"
  version          = "0.30.1"
  namespace        = kubernetes_namespace.spire.metadata[0].name
  create_namespace = false

  depends_on = [helm_release.spire_crds]

  values = [
    yamlencode({
      global = {
        spire = {
          clusterName = "rancher-desktop"
          trustDomain = var.spire_trust_domain
          jwtIssuer   = var.spire_jwt_issuer
          caSubject = {
            country      = "US"
            organization = "Azure-WIF-DevOps"
            commonName   = "example.org"
          }
        }
      }
      spire-server = {
        service = {
          type = "NodePort"
          ports = {
            oidc = {
              port     = 443
              nodePort = 30443
            }
          }
        }
      }
      spiffe-csi-driver = {
        enabled    = true
        pluginName = "csi.spiffe.io"
      }
    })
  ]
}
