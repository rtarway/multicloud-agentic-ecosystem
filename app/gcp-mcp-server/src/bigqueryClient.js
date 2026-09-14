// Google Cloud BigQuery Client for GCP MCP Server
// Supports live Google Cloud BigQuery API execution and deterministic simulation mode
// Integrates with GCP IAM RBAC and Credential Access Boundaries (CAB)

const https = require('https');
const fs = require('fs');

const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID || 'wifdemoproject-507002';
const GCP_DATASET_ANALYTICS = process.env.GCP_DATASET_ANALYTICS || 'analytics_data';
const GCP_DATASET_AUDIT = process.env.GCP_DATASET_AUDIT || 'audit_logs';
const GCP_LIVE_MODE = process.env.GCP_LIVE_MODE === 'true';

class BigQueryClient {
  constructor() {
    this.projectId = GCP_PROJECT_ID;
  }

  /**
   * Executes a live query via Google Cloud BigQuery REST API
   */
  async _executeLiveBigQueryRest(query, accessToken) {
    const postData = JSON.stringify({
      query,
      useLegacySql: false,
      timeoutMs: 15000
    });

    const parsedUrl = new URL(`https://bigquery.googleapis.com/bigquery/v2/projects/${this.projectId}/queries`);
    return new Promise((resolve, reject) => {
      const req = https.request(
        parsedUrl,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
          },
          timeout: 15000
        },
        res => {
          let raw = '';
          res.on('data', chunk => (raw += chunk));
          res.on('end', () => {
            try {
              const parsed = JSON.parse(raw);
              if (res.statusCode >= 200 && res.statusCode < 300) {
                resolve(parsed);
              } else {
                reject(new Error(`GCP BigQuery API error (HTTP ${res.statusCode}): ${parsed.error?.message || raw}`));
              }
            } catch (err) {
              reject(new Error(`Failed to parse BigQuery API response: ${err.message}`));
            }
          });
        }
      );
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('BigQuery API request timed out.'));
      });
      req.write(postData);
      req.end();
    });
  }

  /**
   * Retrieves an access token for live GCP calls
   */
  _getLiveAccessToken(authContext = {}) {
    if (process.env.GCP_ACCESS_TOKEN) {
      return process.env.GCP_ACCESS_TOKEN;
    }
    if (authContext.gcpAccessToken) {
      return authContext.gcpAccessToken;
    }
    return null;
  }

  /**
   * Queries regional sales and customer telemetry from BigQuery dataset 'analytics_data'
   */
  async querySales({ quarter = 'Q2-2026', region = 'north-america', metric = 'revenue_breakdown' }, authContext = {}) {
    const sub = authContext.sub || 'anonymous-user';
    const actorChain = authContext.actorChain || [];

    console.log(`[GCP-BigQuery] 🔍 Executing query on dataset '${GCP_DATASET_ANALYTICS}' for principal '${sub}' (Region: ${region}, Metric: ${metric})...`);

    const liveToken = this._getLiveAccessToken(authContext);

    // If live mode is explicitly enabled and token is provided, execute against live Google Cloud
    if (GCP_LIVE_MODE && liveToken) {
      try {
        console.log(`[GCP-BigQuery] 🌐 Executing LIVE query against Google BigQuery in project '${this.projectId}'...`);
        const sql = `SELECT quarter, region, total_revenue, active_accounts, churn_risk FROM \`${this.projectId}.${GCP_DATASET_ANALYTICS}.regional_sales\` WHERE region = '${region}' LIMIT 10`;
        const bqResult = await this._executeLiveBigQueryRest(sql, liveToken);

        const rows = (bqResult.rows || []).map(r => ({
          quarter: r.f[0]?.v,
          region: r.f[1]?.v,
          totalRevenue: r.f[2]?.v,
          activeAccounts: r.f[3]?.v ? parseInt(r.f[3].v, 10) : null,
          churnRisk: r.f[4]?.v
        }));

        return {
          queryJobId: bqResult.jobReference?.jobId || `bqjob_${Date.now()}`,
          projectId: this.projectId,
          dataset: GCP_DATASET_ANALYTICS,
          table: 'regional_sales',
          cacheHit: bqResult.cacheHit || false,
          totalBytesProcessed: parseInt(bqResult.totalBytesProcessed || '0', 10),
          executionMode: 'LIVE_GOOGLE_CLOUD',
          rowCount: rows.length,
          rows: [
            {
              quarter,
              region,
              metricRequested: metric,
              data: rows[0] || { region, totalRevenue: '$0' },
              verifiedLineage: {
                humanSubject: sub,
                presentingActor: actorChain[0] || 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
                multiHopActors: actorChain
              }
            }
          ]
        };
      } catch (err) {
        console.warn(`[GCP-BigQuery] ⚠️ Live query encountered error (${err.message}). Falling back to simulation fixture.`);
      }
    }

    // Deterministic analytics records aligned with enterprise data (Simulation / hermetic testing)
    const analyticsDatabase = {
      'north-america': {
        quarter,
        region: 'north-america',
        totalRevenue: '$14,250,000',
        topCategories: ['Enterprise Cloud', 'Cybersecurity', 'AI Infrastructure'],
        activeAccounts: 18420,
        churnRiskPercentage: '1.8%',
        yoyGrowth: '+23.4%',
        transactionCount: 142050
      },
      'emea': {
        quarter,
        region: 'emea',
        totalRevenue: '$8,940,000',
        topCategories: ['Data Governance', 'FinOps', 'App Modernization'],
        activeAccounts: 12150,
        churnRiskPercentage: '2.4%',
        yoyGrowth: '+18.1%',
        transactionCount: 98400
      },
      'apac': {
        quarter,
        region: 'apac',
        totalRevenue: '$6,750,000',
        topCategories: ['IoT Analytics', 'Edge Compute', 'Supply Chain'],
        activeAccounts: 9800,
        churnRiskPercentage: '3.1%',
        yoyGrowth: '+28.7%',
        transactionCount: 82300
      },
      'latam': {
        quarter,
        region: 'latam',
        totalRevenue: '$2,310,000',
        topCategories: ['Retail Systems', 'Digital Banking'],
        activeAccounts: 4200,
        churnRiskPercentage: '4.2%',
        yoyGrowth: '+14.5%',
        transactionCount: 31200
      }
    };

    const record = analyticsDatabase[region] || analyticsDatabase['north-america'];

    return {
      queryJobId: `bqjob_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
      projectId: this.projectId,
      dataset: GCP_DATASET_ANALYTICS,
      table: 'regional_sales',
      cacheHit: false,
      totalBytesProcessed: 18450020,
      totalBytesBilled: 20971520,
      executionTimeMs: 142,
      executionMode: 'HERMETIC_SIMULATION',
      rowCount: 1,
      rows: [
        {
          quarter: record.quarter,
          region: record.region,
          metricRequested: metric,
          data: record,
          verifiedLineage: {
            humanSubject: sub,
            presentingActor: actorChain[0] || 'spiffe://example.org/ns/agent-system/sa/orchestrator-sa',
            multiHopActors: actorChain
          }
        }
      ]
    };
  }

  /**
   * Queries BigQuery audit logs and IAM policy evaluations
   * Restricted strictly to administrators with mcp:bigquery:audit
   */
  async queryAuditLogs({ dataset = 'audit_logs', timeRange = 'last_24h', filterActor = null }, authContext = {}) {
    const sub = authContext.sub || 'anonymous-user';
    const roles = authContext.roles || [];
    const scopes = authContext.scopes || [];
    const isAdmin = roles.includes('admin') || roles.includes('BigQuery.Admin') || scopes.includes('mcp:bigquery:audit');

    if (!isAdmin) {
      const err = new Error(`GCP Cloud IAM Access Denied (HTTP 403): Principal '${sub}' lacks 'roles/bigquery.admin' or 'roles/logging.viewer' to inspect dataset '${dataset}'.`);
      err.statusCode = 403;
      throw err;
    }

    console.log(`[GCP-BigQuery] 🛡️ Fetching Audit Logs for Admin principal '${sub}' (TimeRange: ${timeRange})...`);

    return {
      queryJobId: `bqaudit_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
      projectId: this.projectId,
      dataset: GCP_DATASET_AUDIT,
      table: 'cloudaudit_googleapis_com_data_access',
      totalBytesProcessed: 4520010,
      executionTimeMs: 98,
      executionMode: 'HERMETIC_SIMULATION',
      rowCount: 3,
      auditEvents: [
        {
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          serviceName: 'bigquery.googleapis.com',
          methodName: 'google.cloud.bigquery.v2.JobService.InsertJob',
          principalEmail: sub,
          actingServiceAccount: 'gcp-mcp-sa@gcp-wif-agent-poc.iam.gserviceaccount.com',
          callerIp: '10.244.1.18',
          delegationType: 'RFC8693_MULTI_HOP',
          status: 'OK'
        },
        {
          timestamp: new Date(Date.now() - 7200000).toISOString(),
          serviceName: 'iamcredentials.googleapis.com',
          methodName: 'google.iam.credentials.v1.IAMCredentials.GenerateAccessToken',
          principalEmail: 'bob@example.com',
          actingServiceAccount: 'orchestrator-sa@gcp-wif-agent-poc.iam.gserviceaccount.com',
          status: 'OK'
        }
      ]
    };
  }
}

module.exports = new BigQueryClient();
