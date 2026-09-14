# Azure Setup & Workload Identity Federation (WIF) Guide

This document provides a comprehensive, step-by-step guide for provisioning the **Azure Cloud Infrastructure**, configuring **Azure Entra ID Workload Identity Federation (WIF)**, and connecting it to your local **Rancher Desktop SPIRE + Istio Agent Ecosystem**.

---

## 📋 Overview of What Gets Created in Azure

```text
                     Azure Cloud Infrastructure
 ┌─────────────────────────────────────────────────────────────┐
 │  Resource Group: rg-azure-wif-poc                           │
 │                                                             │
 │  1. User-Assigned Managed Identity                          │
 │     └─ id-agent-orchestrator                                │
 │                                                             │
 │  2. Federated Identity Credential (Trust with SPIRE)        │
 │     ├─ Issuer:   https://identity.azure.example.com/spire   │
 │     ├─ Subject:  spiffe://example.org/ns/agent-system/...   │
 │     └─ Audience: api://AzureADTokenExchange                 │
 │                                                             │
 │  3. Azure Storage Account (azwifstoragepoc)                 │
 │     ├─ Container: app1 (Storage Blob Data Contributor)      │
 │     └─ Container: app2 (Storage Blob Data Contributor)      │
 │  4. Low-Code Azure MCP Server (Protocol Spec July 2026)     │
 │     ├─ Runtime: Node.js 22 LTS on Azure (Linux Web App / PaaS)│
 │     └─ Tools:   tool1 (app1/app2 read/write), tool2 (audit) │
 └─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Prerequisites

- **Azure Account & Active Subscription**: You need `Owner` or `User Access Administrator` role on the subscription/resource group to create resources and assign RBAC roles.
- **For Option 1 (CLI Automation)**: [Azure CLI (`az`)](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) installed and logged in (`az login`).
- **For Option 2 (Terraform)**: [Terraform CLI](https://www.terraform.io/downloads) installed and authenticated.
- **For Option 3 (Azure Portal)**: Any web browser logged in to the [Azure Portal (portal.azure.com)](https://portal.azure.com).

---

## 🚀 Option 1: One-Click Automated Script (`azure/wif-setup.sh`)

The fastest way to configure everything in Azure is using the provided automation script:

```bash
# 1. Set environment variables (optional overrides)
export AZURE_RESOURCE_GROUP="rg-azure-wif-poc"
export AZURE_LOCATION="centralus" # Match your storage buckets region (e.g. Central US)
export AZURE_STORAGE_ACCOUNT="azwifstoragepoc$RANDOM" # Must be globally unique alphanumeric
export SPIRE_OIDC_ISSUER="https://identity.azure.example.com/spire-oidc"

# 2. Run the provisioning script
./azure/wif-setup.sh
```

### What `azure/wif-setup.sh` does automatically:
1. Creates Resource Group `rg-azure-wif-poc`.
2. Creates Azure Storage Account with TLS 1.2 enforcement.
3. Creates Blob containers `app1` and `app2`.
4. Creates User-Assigned Managed Identity `id-agent-orchestrator`.
5. Configures the **Federated Identity Credential** on the Managed Identity:
   - **Issuer**: SPIRE OIDC Discovery Endpoint
   - **Subject**: `spiffe://example.org/ns/agent-system/sa/orchestrator-sa`
   - **Audience**: `api://AzureADTokenExchange`
6. Assigns `Storage Blob Data Contributor` RBAC role on containers `app1` and `app2` to the Managed Identity.

---

## 🏗️ Option 2: Terraform Provisioning (`azure/`)

If you prefer Infrastructure-as-Code (Terraform), use the dedicated Azure Terraform module:

```bash
cd azure

# 1. Initialize Azure provider
terraform init

# 2. Preview resources
terraform plan

# 3. Apply infrastructure
terraform apply -auto-approve
```

### Key Terraform Outputs:
- `storage_account_name`: Name of the created storage account.
- `managed_identity_client_id`: Client ID of the federated identity.
- `app1_container_url`: Azure Resource ID for `app1`.
- `app2_container_url`: Azure Resource ID for `app2`.

---

## 🖥️ Option 3: Manual Step-by-Step Setup via Azure Portal

If you prefer using the graphical **Azure Portal** ([portal.azure.com](https://portal.azure.com)), follow these step-by-step instructions.

### Step 1: Create the Resource Group
1. Sign in to the [Azure Portal](https://portal.azure.com).
2. Search for **Resource groups** in the top search bar and select it.
3. Click **+ Create** (top left).
4. Fill in the configuration:
   - **Subscription**: Select your active Azure subscription.
   - **Resource group**: `rg-azure-wif-poc`
   - **Region**: Select your preferred region (e.g. `East US`).
5. Click **Review + create**, then click **Create**.

### Step 2: Create the Azure Storage Account
1. Search for **Storage accounts** in the top search bar and select it.
2. Click **+ Create**.
3. Under the **Basics** tab:
   - **Subscription**: Select your subscription.
   - **Resource group**: Select `rg-azure-wif-poc`.
   - **Storage account name**: Enter a unique lowercase alphanumeric name (e.g. `azwifstoragepoc<unique_suffix>`).
   - **Region**: Same region as resource group (e.g. `East US`).
   - **Primary service**: `Azure Blob Storage or Azure Data Lake Storage Gen 2`.
   - **Performance**: `Standard`.
   - **Redundancy**: `Locally-redundant storage (LRS)`.
4. Under the **Security** tab:
   - Ensure **Minimum TLS version** is set to `Version 1.2`.
5. Click **Review + create**, then click **Create**. Wait for deployment to complete.

### Step 3: Create Storage Containers `app1` and `app2`
1. Go to your newly created Storage Account resource.
2. In the left navigation menu under **Data storage**, click **Containers**.
3. Click **+ Container** (top left):
   - **Name**: `app1`
   - **Anonymous access level**: `Private (no anonymous access)`
   - Click **Create**.
4. Click **+ Container** again:
   - **Name**: `app2`
   - **Anonymous access level**: `Private (no anonymous access)`
   - Click **Create**.
5. *(Optional initial sample data)*:
   - Click into container `app1` -> Click **Upload** -> upload a sample `financial-report.json` or `compliance.txt`.
   - Click into container `app2` -> Click **Upload** -> upload a sample `customer-metrics.json`.

### Step 4: Create User-Assigned Managed Identity
1. Search for **Managed Identities** in the top search bar and select it.
2. Click **+ Create**.
3. Fill in the details:
   - **Subscription**: Select your subscription.
   - **Resource group**: `rg-azure-wif-poc`.
   - **Region**: Same region (e.g. `East US`).
   - **Name**: `id-agent-orchestrator`.
4. Click **Review + create**, then click **Create**.
5. Once created, click **Go to resource**.
6. On the **Overview** page, copy and save:
   - **Client ID** (Application ID)
   - **Object (principal) ID**

### Step 5: Configure Federated Identity Credential (SPIRE Trust)
1. Inside the `id-agent-orchestrator` Managed Identity page, look at the left sidebar under **Settings**.
2. Click **Federated credentials**.
3. Click **+ Add credential**.
4. In the **Federated credential scenario** dropdown, select **Other issuer**.
5. Fill in the trust parameters:
   - **Issuer URL**: Use your **permanent Azure Blob Storage URL** (from the storage account created in Step 2):
     ```text
     https://<YOUR_STORAGE_ACCOUNT_NAME>.blob.core.windows.net/spire-oidc
     ```
     *(For example, if your storage account from Step 2 is `azwifstoragepoc123`, use `https://azwifstoragepoc123.blob.core.windows.net/spire-oidc`)*.
   - **Subject identifier**:
     ```text
     spiffe://example.org/ns/agent-system/sa/orchestrator-sa
     ```
     *(This is the exact SPIFFE ID that SPIRE assigns to the Agent Orchestrator pod)*.
   - **Audience**:
     ```text
     api://AzureADTokenExchange
     ```
     *(Default standard audience for Azure Entra ID workload identity federation)*.
   - **Name**: `fed-cred-spire-orchestrator`
   - **Description**: `Trust federation between SPIRE Workload Identity and Azure Entra ID`
6. Click **Add**.

> [!TIP]
> ### 💡 Why use Azure Blob Storage as your Issuer URL instead of Cloudflare?
> - **The Problem with Cloudflare Tunnels**: Ephemeral tunnels (e.g. `*.trycloudflare.com`) generate a new random URL every time your machine or tunnel restarts. Each restart breaks the Azure Entra ID trust, forcing you to delete and recreate the Federated Credential.
> - **The Azure Blob Storage Solution**: Azure Entra ID only needs to fetch the static OIDC metadata (`/.well-known/openid-configuration`) and the public JWKS keys (`/keys`) over HTTPS. By hosting these two static JSON files in your Azure Storage Account container (`spire-oidc`), you get a **permanent HTTPS URL that never changes on restarts**.
> - **How to prepare the `spire-oidc` container right now in Azure Portal**:
>   1. Go to your Storage Account -> In the left sidebar under **Settings**, click **Configuration**.
>   2. Set **Allow Blob anonymous access** to **Enabled** and click **Save**.
>   3. In the left sidebar under **Data storage**, click **Containers** -> click **+ Container**.
>   4. Name: `spire-oidc`, Anonymous access level: **Blob (anonymous read access for blobs only)** -> click **Create**.
> - Once your Rancher Desktop cluster is running, simply execute `./scripts/publish-spire-oidc.sh` to extract the public keys from SPIRE and automatically upload them to your `spire-oidc` container!

### Step 6: Assign RBAC Role Assignments on Containers `app1` and `app2`
1. Navigate back to your **Storage Account** -> **Containers**.
2. Click on the **`app1`** container.
3. In the left sidebar of the container blade, click **Access Control (IAM)**.
4. Click **+ Add** -> select **Add role assignment**.
5. In the **Role** tab:
   - Search for and select **Storage Blob Data Contributor**.
   - Click **Next**.
6. In the **Members** tab:
   - Under **Assign access to**, select **Managed identity**.
   - Click **+ Select members**.
   - In the right-hand flyout:
     - **Subscription**: Your subscription.
     - **Managed identity**: Select `User-assigned managed identity`.
     - Select `id-agent-orchestrator`.
     - Click **Select**.
7. Click **Review + assign**, then click **Review + assign** again.
8. Now repeat the exact same assignment for **`app2`**:
   - Go to container **`app2`** -> **Access Control (IAM)** -> **+ Add role assignment**.
   - Role: **Storage Blob Data Contributor**.
   - Members: Managed Identity -> `id-agent-orchestrator`.
   - Click **Review + assign**.

---

## 🔗 How Rancher Desktop & SPIRE Connect to Azure

```text
[A2A Agent Orchestrator (Rancher Desktop)]
       │
       │ 1. Workload API fetches SPIRE JWT-SVID
       ▼ (Subject: spiffe://example.org/ns/agent-system/sa/orchestrator-sa)
[Azure Entra ID Token Endpoint (STS)]
       │
       │ 2. Validates SPIRE SVID signature against SPIRE OIDC Discovery
       │ 3. Matches Federated Identity Credential (Subject + Issuer)
       ▼
[Azure Entra ID Access Token]
       │
       │ 4. Scoped to Storage Blob Data Contributor on app1 and app2
       ▼
[Azure Storage Account (app1 & app2 containers)]
```

### 1. Publishing SPIRE OIDC Discovery to Azure
Azure Entra ID requires the SPIRE OIDC discovery documents (`/.well-known/openid-configuration` and `/keys`) to be publicly reachable over HTTPS.
- In production or test environments with public endpoints, set:
  ```bash
  export SPIRE_OIDC_ISSUER="https://<YOUR_PUBLIC_BLOB_OR_DOMAIN>/spire-oidc"
  ```
- The SPIRE stack deployed via `./terraform/spire.tf` includes the OIDC Discovery Provider on NodePort `30443`.

---

### ☁️ Deploying the Low-Code Declarative MCP Server to Azure

> [!IMPORTANT]
> ### 💡 Architecture Overview: External Agent with Azure MCP Server
> For the purpose of this POC:
> - **The Goal**: Prove that an **external agent ecosystem** deployed on **Rancher Desktop Kubernetes** can authenticate to an Azure-deployed MCP Server using an **RFC 8693 downscoped On-Behalf-Of (OBO) token** (`sub` = human user, `act.sub` = agent SPIFFE ID).
> - **Direct HTTPS Connection**: The Rancher Desktop agent communicates directly with the MCP server over HTTPS (`/mcp` endpoint) on Azure App Service.
> - **Zero Account Keys**: Storage access uses short-lived (60s TTL) JIT User-Delegation credentials bound to the caller's Entra identity and token signature.

---

### Step 1: Set Up Azure CLI Authentication & Subscription

Before running deployment scripts or CLI commands, ensure your Azure CLI is logged in and pointed to your desired subscription:

```bash
# 1. Log in to Azure (opens browser window)
az login

# 2. List your available subscriptions
az account list --output table

# 3. Set your active subscription
az account set --subscription "<YOUR_SUBSCRIPTION_ID_OR_NAME>"

# 4. Verify active subscription
az account show --output table
```

---

### Step 2: Deploy the MCP Server to Azure

The MCP server runs the declarative `tools.yaml` (protocol version `2026-07-15`) and exposes the JSON-RPC `/mcp` endpoint. You have 3 deployment options:

#### Option A: One-Command Automated Script (`./scripts/deploy-azure-mcp.sh`) - Recommended
This script checks authentication, deploys the code to Azure App Service in `Central US` (matching your storage buckets), configures environment variables, and verifies `/healthz`:

```bash
# Optional overrides (defaults to centralus and rg-azure-wif-poc)
export AZURE_RESOURCE_GROUP="rg-azure-wif-poc"
export AZURE_LOCATION="centralus"
export AZURE_STORAGE_ACCOUNT="<YOUR_STORAGE_ACCOUNT_NAME>"

# Run automated deployment
./scripts/deploy-azure-mcp.sh
```

#### Option B: Manual Setup via Azure Portal ([portal.azure.com](https://portal.azure.com))
If you prefer configuring through the graphical Azure Portal:

1. **Create the Web App**:
   - Go to [portal.azure.com](https://portal.azure.com) &rarr; Search **App Services** &rarr; Click **+ Create** &rarr; **Web App**.
   - **Subscription**: Your active subscription.
   - **Resource Group**: Select your resource group (e.g. `rg-azure-wif-poc`).
   - **Name**: Enter a unique name, e.g. `az-mcp-server-<unique>`.
   - **Publish**: `Code`.
   - **Runtime stack**: `Node 22 LTS`.
   - **Operating System**: `Linux`.
   - **Region**: **Central US** (same region as your storage account).
   - **Pricing Plan**: `Basic B1` (or Free F1 for testing).
   - Click **Review + create** &rarr; **Create**.

2. **Configure Environment Variables**:
   - Navigate to your newly created Web App &rarr; In the left sidebar under **Settings**, click **Environment variables** (or **Configuration**).
   - Add the following App Settings:
     | Name | Value | Purpose |
     | :--- | :--- | :--- |
     | `PORT` | `8080` | Server listening port |
     | `WEBSITES_PORT` | `8080` | Directs Azure router to port 8080 |
     | `SCM_DO_BUILD_DURING_DEPLOYMENT` | `true` | Runs npm install during deployment |
     | `MCP_PROTOCOL_VERSION` | `2026-07-15` | MCP July 2026 Protocol Specification |
     | `AZURE_STORAGE_ACCOUNT` | `<YOUR_STORAGE_ACCOUNT_NAME>` | Storage account with `app1` and `app2` |
     | `JWT_SECRET` | `demo-obo-token-secret-key-2026` | Secret for verifying OBO tokens |
     | `NODE_ENV` | `production` | Node environment |
   - Click **Apply** (or **Save**).

3. **Deploy the Code via Azure CLI**:
   - Package and deploy cleanly:
     ```bash
     cd app/mcp-server
     zip -q -r /tmp/deploy.zip . -x "node_modules/*" -x ".git/*" -x "test/*" -x "test.sock"
     az webapp deploy \
       --name "<YOUR_APP_NAME>" \
       --resource-group "rg-azure-wif-poc" \
       --src-path /tmp/deploy.zip \
       --type zip \
       --clean true \
       --restart true
     rm -f /tmp/deploy.zip
     ```

#### Option C: Local / Zero-Cost Simulation Mode (Offline / Pre-Cloud)
You can run and test the complete agentic flow without deploying anything to Azure compute:
```bash
# 1. Run the complete end-to-end CLI demonstration (offline emulator)
./scripts/run-demo.sh

# 2. Or start the MCP server locally on port 8080:
cd app/mcp-server && npm start
```

---

### Step 3: Verify the Deployed Azure MCP Server

Once deployed, test your live endpoint directly from your terminal:

1. **Verify Health Check**:
   ```bash
   curl -s https://<YOUR_APP_NAME>.azurewebsites.net/healthz
   # Output: {"status":"UP","protocolVersion":"2026-07-15","toolsRegistered":2}
   ```

2. **Verify MCP Protocol Tools List (`2026-07-15` Spec)**:
   ```bash
   curl -s -X POST https://<YOUR_APP_NAME>.azurewebsites.net/mcp \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
   ```
   You will receive the JSON-RPC response listing `tool1` (read/write on `app1` and `app2`) and `tool2` (read-only audit on `app1`).

---

### Step 4: Deploy the Agent Ecosystem & SPIRE onto Rancher Desktop Kubernetes

Now that your Azure MCP Server is live and verified, deploy the local Agent Ecosystem (Keycloak IdP, SPIRE + Istio Workload Identity, Agent Orchestrator, and Web Frontend) into Rancher Desktop.

#### ⚙️ How Kubernetes Reads the Azure Endpoint Dynamically (No File Editing)

The Kubernetes deployment (`k8s/agent-orchestrator-deployment.yaml`) dynamically reads `MCP_SERVER_URL` from the **`agent-config` ConfigMap** using `configMapKeyRef`:

```yaml
env:
  - name: MCP_SERVER_URL
    valueFrom:
      configMapKeyRef:
        name: agent-config
        key: MCP_SERVER_URL
        optional: true
```

You **never** have to modify YAML files manually. The endpoint can be dynamically set or updated with a single command:

```bash
# Update the ConfigMap to point to your deployed Azure MCP Server
kubectl create configmap agent-config -n agent-system \
  --from-literal=MCP_SERVER_URL="https://<YOUR_APP_NAME>.azurewebsites.net/mcp" \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart the orchestrator to pick up the updated URL
kubectl rollout restart deployment/agent-orchestrator -n agent-system
```

---

#### 🚀 Deployment Option 1: 1-Click Automated Script (`./scripts/install-infra.sh`) - Recommended

The automated script configures the entire local stack and connects it to your Azure resources:

```bash
# 1. Set your Azure resources
export AZURE_STORAGE_ACCOUNT="<YOUR_STORAGE_ACCOUNT_NAME>"
export AZURE_MCP_ENDPOINT="https://<YOUR_APP_NAME>.azurewebsites.net/mcp"

# 2. Run the end-to-end infrastructure installer
./scripts/install-infra.sh
```

**What this script does automatically:**
1. Verifies local tools (`kubectl`, `terraform`, `helm`, `docker`) and ensures Rancher Desktop Kubernetes is active.
2. Applies Terraform (`terraform/`) to provision:
   - **SPIRE Server & Agent** with the SPIFFE CSI Driver.
   - **Istio Service Mesh** with SPIRE Workload Identity integration.
   - **Keycloak IdP** in namespace `keycloak` with pre-loaded users (`alice` [Admin] and `bob` [Regular User]).
3. Builds local Docker container images in Rancher Desktop:
   - `agent-orchestrator:v1.0.0`
   - `web-frontend:v1.0.0`
4. Deploys Kubernetes workloads (`k8s/`):
   - Creates namespaces: `agent-system`, `keycloak`.
   - Creates `agent-config` ConfigMap populated with your `AZURE_MCP_ENDPOINT`.
   - Deploys `agent-orchestrator` (with SPIRE socket injection and Istio sidecar).
   - Deploys `web-frontend` (outside SPIRE, accessible via browser).
5. Publishes SPIRE OIDC Discovery documents and public JWKS keys to Azure Blob Storage (`./scripts/publish-spire-oidc.sh`) so Azure Entra ID can validate SPIRE SVIDs.
6. Waits for all pods to be in `Ready` state and configures port-forwarding.

---

#### 📋 Deployment Option 2: Step-by-Step Manual Deployment

If you prefer executing each step manually:

##### 1. Create Kubernetes Namespaces
```bash
kubectl apply -f k8s/namespaces.yaml
```

##### 2. Provision SPIRE, Istio, and Keycloak via Terraform
```bash
cd terraform
terraform init
terraform apply -auto-approve
cd ..
```
*Wait ~60 seconds for SPIRE server (`spire-server-0`) and Keycloak pods to be ready.*

##### 3. Build Local Container Images
```bash
docker build -t agent-orchestrator:v1.0.0 app/agent-orchestrator
docker build -t web-frontend:v1.0.0 app/web-frontend
```

##### 4. Configure Azure MCP Endpoint in ConfigMap
```bash
kubectl create configmap agent-config -n agent-system \
  --from-literal=MCP_SERVER_URL="https://<YOUR_APP_NAME>.azurewebsites.net/mcp" \
  --dry-run=client -o yaml | kubectl apply -f -
```

##### 5. Deploy Workloads
```bash
kubectl apply -f k8s/agent-orchestrator-deployment.yaml
kubectl apply -f k8s/web-frontend-deployment.yaml

# Verify pods are running
kubectl get pods -n agent-system
```

##### 6. Publish SPIRE OIDC Discovery to Azure Blob Storage
Azure Entra ID Workload Identity Federation requires SPIRE's public keys to be reachable over HTTPS:
```bash
export AZURE_STORAGE_ACCOUNT="<YOUR_STORAGE_ACCOUNT_NAME>"
./scripts/publish-spire-oidc.sh
```

##### 7. Access the Application
- **Web Frontend UI (Outside SPIRE)**:
  ```bash
  kubectl port-forward -n agent-system svc/web-frontend 3000:3000
  ```
  Open **http://localhost:3000** in your browser.
- **Keycloak Admin Console**:
  ```bash
  kubectl port-forward -n keycloak svc/keycloak-service 8080:8080
  ```
  Open **http://localhost:8080** (Admin: `admin` / `admin`).

---

### Step 5: Test the End-to-End Flow (Web UI & CLI)

#### A. Interactive Testing via Web UI (`http://localhost:3000`)
1. Navigate to `http://localhost:3000`.
2. **Log in as Bob (Regular User)**:
   - Prompt: *"Write monthly summary to app2"* &rarr; **Granted** (Tool1).
   - Prompt: *"Audit container app1"* &rarr; **Denied** (Tool2 requires `mcp:tool2`, Bob only has `mcp:tool1`).
3. **Log in as Alice (Security Admin)**:
   - Prompt: *"Audit container app1"* &rarr; **Granted** (Alice has `mcp:tool2`).

#### B. Direct CLI Demonstration against Azure MCP Server
You can also run the automated test scenario directly against your deployed Azure MCP Server:
```bash
export AZURE_MCP_ENDPOINT="https://<YOUR_APP_NAME>.azurewebsites.net/mcp"
./scripts/run-demo.sh
```

## 🔍 Verification & Troubleshooting

### 1. Verify Managed Identity & Federated Credentials
```bash
# Check the Managed Identity
az identity show \
  --name "id-agent-orchestrator" \
  --resource-group "rg-azure-wif-poc"

# Check the Federated Identity Credential
az identity federated-credential list \
  --identity-name "id-agent-orchestrator" \
  --resource-group "rg-azure-wif-poc" \
  --output table
```

### 2. Verify Storage Container RBAC
```bash
az role assignment list \
  --assignee "<MANAGED_IDENTITY_PRINCIPAL_ID>" \
  --output table
```
You should see two role assignments for `Storage Blob Data Contributor` scoped to `app1` and `app2`.

### 3. Test Local Simulation Mode (Offline / Pre-Cloud)
You do **not** need an active Azure subscription to test the logic! The built-in emulator in `azureStorage.js` lets you test everything immediately:
```bash
./scripts/run-demo.sh
```
All OBO token exchanges, scope downscoping, and MCP tool execution will execute locally with 100% fidelity.
