# POC Setup Guide: Manual Steps

Terraform and scripts in this repo provision what can be automated. This guide lists everything that **must be done by hand** (tenant, console and account actions), in order, plus how to verify each step. It supports Phase 1 of [`security-remediation-plan.md`](./security-remediation-plan.md).

In the real enterprise none of the identity steps apply: users, groups and roles are already synced to Entra and Google, and Azure is federated to the enterprise IdP. Here the POC runs on Rancher Desktop with no enterprise organization, so you create stand-ins.

Values in `<angle brackets>` are yours to choose or look up. **Never commit secrets.** Put them in untracked files (`*.auto.tfvars`, `.env.*`) or a secret store. Confirm `.gitignore` covers them before you start.

## 0. Prerequisites

Tools on your machine:
- Rancher Desktop (Kubernetes enabled), `kubectl`, `helm`, `terraform` >= 1.5, `docker`, Node.js 20
- `az` (Azure CLI) and `gcloud` (with `bq`)

Accounts:
- An **Azure subscription** and an **Entra test tenant** in which you hold Global Administrator (or equivalent roles listed in section 3).
- A **Google Cloud project** with billing enabled. No organization is needed.
- **One real Google account per test user** (for example `alice.test@gmail.com`). You will add these as OAuth test users. Terraform cannot create Google accounts.

Decide your test users once, in `identity/users.yaml` (created in Phase 1). Keep the same logical user, with the same email wherever possible, in all three systems.

## 1. Decide URLs (do this first)

Several consoles ask for exact redirect URLs. Fix them now:

| Item | Example | Used by |
|---|---|---|
| Web frontend (BFF) | `http://localhost:3000` | Keycloak and Entra redirect URIs |
| Keycloak | `http://localhost:8080` (port-forward) | frontend, orchestrator |
| Azure MCP | `https://<app>.azurewebsites.net` | Entra API audience |
| GCP MCP | `https://<service>-<hash>-uc.a.run.app` | Google OAuth redirect URI |
| SPIRE OIDC issuer | `https://<storage>.blob.core.windows.net/spire-oidc` | Entra federated credential |

Google allows `http://localhost` redirect URIs for web clients, which is useful for local runs of the GCP MCP, but the deployed Cloud Run URL needs its own entry.

## 2. Rancher Desktop and the local stack

1. Start Rancher Desktop with Kubernetes enabled; confirm `kubectl config current-context` is `rancher-desktop`.
2. Run `./scripts/install-infra.sh` (SPIRE, Istio, Keycloak, workloads).
3. Port-forward Keycloak: `kubectl -n keycloak port-forward svc/keycloak-service 8080:8080`.
4. Load the Keycloak admin credentials. `install-infra.sh` generates them once into the git-ignored `.env.keycloak` (user `kcadmin`, random password); there is no default password. `source .env.keycloak` before running Terraform or the Keycloak scripts. Rotate the password in the admin console if you share the machine.

**Keycloak version:** the cluster now runs Keycloak 26.2 or later (`var.keycloak_image`, default `quay.io/keycloak/keycloak:26.2.5`; confirm that tag is available to you or set another 26.2+ tag). That release provides supported standard token exchange, which the orchestrator uses. Do not enable the legacy `token-exchange` feature. `KC_HOSTNAME` is pinned to `var.keycloak_public_url` (default `http://localhost:8080`) so every token's `iss` is identical whether it was obtained through the browser or from inside the cluster; if you port-forward Keycloak to a different local port, set that variable and `OIDC_ISSUER` in `k8s/oidc-config.yaml` to match.

Verify: `kubectl get pods -A` shows SPIRE, Istio and Keycloak pods running.

## 3. Azure and Entra (manual parts)

### 3.1 Sign in and permissions
1. `az login --tenant <tenant-id>`; select the subscription with `az account set -s <subscription-id>`.
2. The identity running Terraform's `azuread` provider needs directory permissions to create users, groups, app registrations and consents. The simplest option for a test tenant is to run as a Global Administrator. If you use a service principal instead, grant it these Microsoft Graph application permissions and give admin consent: `User.ReadWrite.All`, `Group.ReadWrite.All`, `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`, `Directory.Read.All`.
3. Use a verified or default domain (`<tenant>.onmicrosoft.com`) for test-user UPNs.

### 3.2 Security defaults and MFA
- A new tenant has **security defaults** on, which require MFA registration at first sign-in. The auth-code flow handles MFA; the old password grant does not, and it is being removed (plan Phase 3).
- For a quick POC you can leave security defaults on and register MFA for each test user once. Do not disable them tenant-wide unless this is a throwaway tenant.

### 3.3 Federation stand-in
- Your enterprise Entra is federated to the enterprise IdP, so sign-in is silent. The test tenant is **not** federated to Keycloak. Test users sign in to Entra interactively at login (a popup or redirect), once per session.
- This is a documented stand-in. In the enterprise the same code runs with `prompt=none`.

### 3.4 SPIRE OIDC issuer (for the SPIFFE client assertion)
Entra must be able to fetch the SPIRE OIDC discovery document and keys over public HTTPS.
1. Run `./scripts/publish-spire-oidc.sh`. It publishes the documents to an Azure Blob container with **public** read.
2. Check that `<issuer>/.well-known/openid-configuration` loads in a browser.
3. Make sure the issuer URL equals `terraform/variables.tf:spire_jwt_issuer` and `azure/variables.tf:spire_oidc_issuer_url`.

Note: the script enables public blob access on the storage account. Use a **separate** storage account for this, not the one holding the app1/app2 containers, and delete the public container when you finish the POC.

### 3.5 Admin consent
After Terraform creates the app registrations (Phase 1), a tenant admin must confirm consent:
- Azure Portal -> Entra ID -> Enterprise applications -> <orchestrator app> -> Permissions -> **Grant admin consent**. (If you manage the delegated permission grants with `azuread_service_principal_delegated_permission_grant`, this is automatic.)
- For the Azure MCP app, add the orchestrator's client ID to its **pre-authorized client applications** so no user consent prompt appears.

### 3.6 Redirect URIs
In the orchestrator/BFF app registration add the web redirect URI `http://localhost:3000/auth/entra/callback` (adjust to your chosen URL). Use the **Web** platform for a confidential client, not SPA.

Verify: a test user can sign in to `https://myapps.microsoft.com` once and complete MFA registration.

### 3.7 Phase 3 apply order (Azure and Entra)
1. `terraform -chdir=azure apply -var spire_oidc_issuer_url=<issuer> -var 'allowed_ip_ranges=["<your public IP>"]'` (the storage network default is Deny; include the Terraform runner and the MCP's outbound IPs). Note outputs `mcp_managed_identity_id`, `mcp_managed_identity_client_id`, `mcp_managed_identity_principal_id`, `oidc_issuer_url`. Your own account needs a Blob data-plane role because shared key is disabled.
2. `./scripts/publish-spire-oidc.sh` (uses the separate account `AZURE_OIDC_STORAGE_ACCOUNT`).
3. `terraform -chdir=terraform/identity/entra apply -var manage_entra_apps=true -var spire_oidc_issuer_url=<issuer> -var mcp_managed_identity_principal_id=<principal id> ...` (see section 5.3).
4. `./scripts/sync-entra-config.sh` to create the `entra-config` ConfigMap, then restart the orchestrator and web-frontend.
5. `AZURE_MCP_IDENTITY_ID=<mcp_managed_identity_id> ./scripts/deploy-azure-mcp.sh`; set App Service settings `ENTRA_CLIENT_ID`, `ENTRA_TENANT_ID`, `AZURE_MI_CLIENT_ID`, `SPIRE_OIDC_ISSUER` (the script sets what it can).
6. Optional CI deploy: set repository variable `AZURE_DEPLOY_ENABLED=true` and `AZURE_CLIENT_ID/TENANT_ID/SUBSCRIPTION_ID/RESOURCE_GROUP/MCP_IDENTITY_ID`, plus a federated credential for the GitHub repo.

## 4. Google Cloud (manual parts)

### 4.1 Project and APIs
```bash
gcloud auth login
gcloud config set project <project-id>
gcloud services enable bigquery.googleapis.com secretmanager.googleapis.com \
  cloudkms.googleapis.com run.googleapis.com iamcredentials.googleapis.com
```

### 4.2 OAuth consent screen (cannot be done in Terraform for external apps)
1. Console -> APIs & Services -> **OAuth consent screen**.
2. User type **External** (no organization means Internal is not available). Publishing status **Testing**.
3. App name, support email and developer email.
4. Scopes: `openid`, `email`, and `https://www.googleapis.com/auth/bigquery.readonly`. Do not add `cloud-platform`.
5. **Test users:** add the Google account of every POC user. Only these accounts can complete consent. Limit: 100.
6. Known limits of Testing mode: refresh tokens **expire after 7 days**, and test users see an "unverified app" warning. Re-consent weekly; this is expected.

### 4.3 OAuth client
1. APIs & Services -> Credentials -> **Create credentials -> OAuth client ID** -> type **Web application**.
2. Authorized redirect URIs: `https://<gcp-mcp-url>/oauth/google/callback` and, for local runs, `http://localhost:8081/oauth/google/callback`.
3. Copy the client ID and secret. Store the secret in Secret Manager, not in a file:
   ```bash
   printf '%s' '<client-secret>' | gcloud secrets create google-oauth-client-secret --data-file=-
   ```

### 4.4 KMS key for the grant vault
```bash
gcloud kms keyrings create agent-mcp --location us-central1
gcloud kms keys create user-grants --keyring agent-mcp --location us-central1 --purpose encryption
```
Terraform (Phase 4) grants the GCP MCP's service account encrypt/decrypt on this key and access to secrets with the grant name prefix. Do not grant anything broader by hand.

### 4.5 BigQuery access for the test users
- Their Google accounts must exist before Terraform binds roles by email; otherwise IAM rejects the binding.
- `terraform/identity/google` (section 5.4) grants dataset-scoped `bigquery.dataViewer` on `analytics_data` only. Grant the audit dataset to a different test user only.
- Each user also needs `roles/bigquery.jobUser` on the project to run queries.

### 4.6 Cleanup of the old federation
Once Phase 4 is done, remove the old pool, provider and service-account binding (`terraform/gcp/main.tf`, `scripts/setup-gcp-wif.sh`). Until then they are harmless but unused.

Verify: `bq query` as a test user (via `gcloud auth login` as that account) returns rows from `analytics_data.regional_sales` and is denied on `audit_logs`.

## 5. Identity seed: Keycloak, Entra and Google from one file

In the enterprise, users, groups and roles are already synced into the IdP, Entra and Google. On the POC you stand that sync in with `identity/users.yaml`, which Terraform applies to all three systems (`terraform/identity/{keycloak,entra,google}`). Nothing secret lives in that file.

### 5.1 Edit the user file
1. Open `identity/users.yaml`. Keep the three personas or change them.
2. Set `settings.entra_default_domain` to your test tenant's domain and make every `emails.entra_upn` end with it.
3. Replace each `emails.google` placeholder (`*@example.com`) with a **real Google account** you control. The Google Terraform root refuses to apply while placeholders remain. A user without BigQuery groups (Charlie) needs no Google account.
4. Regenerate the derived map and run the offline checks:
   ```bash
   node scripts/identity-build-map.js
   node scripts/identity-check.js
   ```

### 5.2 Keycloak
```bash
source .env.keycloak                       # TF_VAR_keycloak_admin_user / _password
kubectl -n keycloak port-forward svc/keycloak-service 8080:8080 &
terraform -chdir=terraform/identity/keycloak init
terraform -chdir=terraform/identity/keycloak apply
```
Creates the realm, groups, users (without credentials), one realm role per agent scope, the `web-frontend` PKCE client with **Consent Required** and the optional `mcp:*` scopes, and the `agent-orchestrator-client` / `mcp-azure-service` clients. Manual steps afterwards:
1. Set a password for each test user (admin console -> Users -> <user> -> Credentials, mark it temporary) and sign in once at `/realms/azure-wif-realm/account` to change it. Do not put passwords in Terraform files or the repo.
2. Confirm `web-frontend` has **Direct access grants** off and **Consent required** on.
3. Confirm the account console lets a user see and revoke the agent's granted scopes.

### 5.2b Connect the services to Keycloak (Phase 2)
After the Keycloak apply:
```bash
./scripts/sync-orchestrator-secret.sh          # copies the orchestrator's client secret into the cluster and restarts it
kubectl apply -f k8s/oidc-config.yaml          # issuer, JWKS/token endpoints, SPIRE issuer (install-infra.sh also does this)
curl -s http://localhost:8080/realms/azure-wif-realm/.well-known/openid-configuration | head -c 300
```
The `iss` in that document must equal `OIDC_ISSUER` in `k8s/oidc-config.yaml` exactly. Open `http://localhost:3000`, choose **Sign in**, accept the consent screen, and the dashboard shows your identity and the scopes you consented to. The browser never holds a token.

To inspect an exchanged token while debugging, decode it in the orchestrator logs' redacted output or request one yourself (standard token exchange against `/protocol/openid-connect/token` with the orchestrator client credentials). It must have exactly one `aud` (the MCP client id), exactly one `mcp:*`/`Mail.Send` scope, `act.sub` equal to the orchestrator's SPIFFE ID, and a lifetime of at most 5 minutes; the orchestrator rejects anything else.

### 5.3 Entra
```bash
az login --tenant <tenant-id>
terraform -chdir=terraform/identity/entra init
terraform -chdir=terraform/identity/entra apply -var storage_account_name=<account> -var resource_group_name=<rg>
```
Creates the users, `poc-<group>` security groups, memberships, and **group-level** Storage RBAC on the app1/app2 containers. Each user gets a random initial password that must be changed at first sign-in; read it deliberately with `terraform -chdir=terraform/identity/entra output -json initial_passwords` (it also lives in the local, git-ignored Terraform state, so protect that file). To let Terraform create the orchestrator and Azure MCP app registrations and admin consent on a fresh tenant, add `-var manage_entra_apps=true` (default off, because the repo's existing apps were made by `scripts/setup-entra-wif.sh`).

### 5.4 Google
```bash
terraform -chdir=terraform/identity/google init
terraform -chdir=terraform/identity/google apply -var gcp_project_id=<project-id>
```
Binds dataset-scoped BigQuery roles (and project `jobUser`) to each user's own Google account. The BigQuery datasets must already exist (`terraform/gcp`).

### 5.5 Verify and offboard
```bash
node scripts/identity-check.js --live      # needs KEYCLOAK_URL/KEYCLOAK_ADMIN_*, `az login`, `bq` and GCP_PROJECT_ID
node scripts/identity-offboard.js bob      # dry run
node scripts/identity-offboard.js bob --apply
```
`--live` confirms each user exists with the right enabled state in Keycloak and Entra and holds exactly the expected BigQuery grants. The offboard script disables the user in all three systems through Terraform, ends their Keycloak sessions, and calls the grant-purge hook once the Google grant vault exists (Phase 4). Set `enabled: false` in `identity/users.yaml` afterwards so later applies keep the user disabled.

## 6. Secrets and where they go

| Secret | Where it lives |
|---|---|
| Keycloak admin password | `.env.keycloak` (git-ignored, generated); stored in the cluster as the `keycloak-admin` Secret |
| Keycloak and Entra user passwords | Keycloak: entered by hand; Entra: random, in local Terraform state until changed at first sign-in |
| Entra client assertion | Not a stored secret; signed by the SPIFFE SVID |
| Google OAuth client secret | Secret Manager (`google-oauth-client-secret`) |
| Per-user Google grants | Secret Manager, encrypted with the KMS key |
| Terraform variables with IDs or emails | Untracked `*.auto.tfvars` |

Check before every commit: `git status` shows no `.env*`, `*.tfvars`, `*.pem` or key files. Rotate anything that was ever committed (several keys in `certs/` are, per Phase 0).

## 7. Verification checklist (after Phases 1-2)

1. `identity/users.yaml` lists each user; `node scripts/identity-check.js --live` reports each one present in Keycloak, Entra and Google with the expected grants.
2. A test user signs in through Keycloak (no minted tokens), and the orchestrator rejects a hand-edited token.
3. The test user completes the Entra sign-in; the Azure MCP returns the `app1` file for a user in the right group and denies one who is not.
4. First BigQuery call returns `authorization_required`; after Google consent, the retry succeeds.
5. Using a different Google account to complete the consent link is rejected (email mismatch).
6. Revoking the grant (or the offboard target) makes the next call return `authorization_required` again, and the stored secret is gone.
7. `kubectl logs` for the orchestrator and both MCPs contain no token strings.

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| Google `redirect_uri_mismatch` | The redirect URI in the OAuth client does not exactly match the MCP's callback URL, including scheme, port and path |
| Google `access_denied` / "app not verified" with no continue option | The signing-in account is not in the test-user list |
| Google `invalid_grant` after about a week | Testing-mode refresh tokens expire after 7 days; re-run the consent |
| Entra `AADSTS65001` | Admin consent is missing for the orchestrator -> MCP permission, or the pre-authorized client is not set |
| Entra `AADSTS50076` / `AADSTS50079` | MFA or MFA registration required; sign in interactively once |
| Entra `AADSTS700211` / federated credential errors | The issuer URL or the subject does not match the federated credential exactly, or the OIDC discovery document is not public |
| BigQuery 403 for a user who should have access | Role granted at project instead of dataset, wrong email bound, or `jobUser` missing |
| Terraform `azuread` 403 | The identity lacks the Graph permissions in section 3.1 |
| Orchestrator `BAD_ISSUER` | `OIDC_ISSUER` differs from the token's `iss` (port-forward on another port, or `KC_HOSTNAME` not applied). Compare with the discovery document |
| Orchestrator `BAD_AUDIENCE` / `BAD_AUTHORIZED_PARTY` | The `agent-identity` scope's audience mapper is missing from `web-frontend`, or the token came from another client. Re-apply `terraform/identity/keycloak` |
| `EXCHANGED_TOKEN_AUDIENCE` / `EXCHANGED_TOKEN_SCOPE` | Keycloak added an audience or an extra agent scope to the exchanged token. Check that the orchestrator client has only `profile` and `email` as default scopes and the agent scopes as optional scopes |
| `EXCHANGED_TOKEN_ACTOR` | The `actor-spiffe-id` mapper is missing on the orchestrator client, or `orchestrator_spiffe_id` differs from the SVID's SPIFFE ID |
| `IDP_EXCHANGE_REJECTED` (HTTP 400/401/403) | `standard.token.exchange.enabled` is off for the orchestrator client, the secret in `orchestrator-oidc` is stale (re-run `sync-orchestrator-secret.sh`), or the subject token does not list the orchestrator in `aud` |
| `Cannot reach the SPIRE agent` | The SPIFFE CSI volume is not mounted at `/run/spire/sockets`, or the pod has no registration entry (check the SPIRE server's registered entries for the orchestrator service account) |
| Orchestrator `ENTRA_IDENTITY_MISMATCH` / `ENTRA_USER_MISMATCH` | The Entra account the user signed in with is not the UPN mapped to their Keycloak identity in `identity-map.json` |
| `STEP_UP_REQUIRED` | Entra returned a claims challenge (MFA, Conditional Access); click Connect Azure / retry in the UI to satisfy it |
| Azure MCP `403 AuthorizationPermissionMismatch` | The user's Entra group has no Storage role on that container, or the storage firewall blocks the MCP's outbound IP |
| `CLIENT_ASSERTION_UNAVAILABLE` | Managed identity not assigned to the App Service, or `AZURE_FEDERATED_TOKEN_FILE` / `SPIRE_OIDC_ISSUER` missing |
| MCP server: `JWT-SVID rejected` | `SPIRE_OIDC_ISSUER` is wrong or unreachable from the pod, or the SVID audience differs from `SVID_AUDIENCE` (`gcp-mcp-server` / `azure-mcp-server`) |

## 9. Teardown

1. `terraform destroy` in each Terraform directory; run the offboard target first so stored grants are purged.
2. Delete the public SPIRE OIDC blob container.
3. Remove test users from the OAuth consent screen and revoke the OAuth client.
4. Delete the KMS key version(s) and the secrets created for grants.
