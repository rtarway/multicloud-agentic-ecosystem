// Microsoft Graph API Client & Outbound Email Delivery Dispatcher
// Executed directly by the Agent Orchestrator upon RFC 8693 token exchange.

const https = require('https');

/**
 * Call Microsoft Graph API directly from the Orchestrator with the RFC 8693 exchanged token,
 * and dispatch physical email via Resend or SendGrid (Option 1).
 * 
 * @param {Object} options
 * @param {string} options.graphToken - RFC 8693 downscoped Bearer token (aud: https://graph.microsoft.com, scope: Mail.Send)
 * @param {string} options.recipient - Target email recipient (strictly rtarway@gmail.com)
 * @param {string} options.subject - Email subject
 * @param {string} options.body - Sanitized/redacted email body
 * @param {Object} [options.emailConfig] - Optional client configuration (resendApiKey, sendgridApiKey, fromEmail)
 * @returns {Promise<Object>} Execution result containing Graph API telemetry and physical delivery receipt
 */
async function dispatchGraphEmail({ graphToken, recipient, subject, body, emailConfig = {} }) {
  console.log(`\n=============================================================`);
  console.log(`[ORCH-GRAPH] 🌐 Orchestrator Calling Microsoft Graph API:`);
  console.log(`[ORCH-GRAPH]   Endpoint:  https://graph.microsoft.com/v1.0/me/sendMail`);
  console.log(`[ORCH-GRAPH]   Recipient: ${recipient}`);
  console.log(`[ORCH-GRAPH]   Subject:   ${subject}`);

  // 1. Live Microsoft Graph API Outbound HTTPS Request
  const liveGraphRes = await callLiveMicrosoftGraphApi({
    token: graphToken,
    recipient,
    subject,
    body
  });

  console.log(`[ORCH-GRAPH]   Graph Status: ${liveGraphRes.status} ${liveGraphRes.statusText}`);
  if (liveGraphRes.headers?.['x-ms-ags-diagnostic']) {
    console.log(`[ORCH-GRAPH]   Azure Diagnostic: ${liveGraphRes.headers['x-ms-ags-diagnostic']}`);
  }

  // 2. Option 1 Physical Email Delivery Dispatcher
  const deliveryRes = await dispatchPhysicalEmail({
    recipient,
    subject,
    body,
    config: emailConfig
  });

  return {
    graphApiStatus: liveGraphRes.status,
    graphApiStatusText: liveGraphRes.statusText,
    graphHeaders: liveGraphRes.headers,
    liveCallAttempted: liveGraphRes.liveCallAttempted,
    endpoint: 'https://graph.microsoft.com/v1.0/me/sendMail',
    deliveredTo: recipient,
    subject,
    dispatchedAt: new Date().toISOString(),
    deliveryRelay: deliveryRes,
    graphPayload: {
      message: {
        subject,
        body: { contentType: 'Text', content: body },
        toRecipients: [{ emailAddress: { address: recipient } }]
      },
      saveToSentItems: 'true'
    }
  };
}

async function callLiveMicrosoftGraphApi({ token, recipient, subject, body }) {
  if (!token || (process.env.NODE_ENV === 'test' && !process.env.TEST_LIVE_AZURE)) {
    return {
      status: 202,
      statusText: 'Accepted (Simulated Test Mode)',
      liveCallAttempted: false,
      headers: {
        'x-ms-ags-diagnostic': 'simulated-azure-diagnostic-2026',
        'request-id': 'simulated-graph-req-id'
      }
    };
  }

  return new Promise(resolve => {
    const payload = JSON.stringify({
      message: {
        subject,
        body: { contentType: 'Text', content: body },
        toRecipients: [{ emailAddress: { address: recipient } }]
      },
      saveToSentItems: 'true'
    });

    const req = https.request(
      'https://graph.microsoft.com/v1.0/me/sendMail',
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 4000
      },
      res => {
        let resData = '';
        res.on('data', chunk => (resData += chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            statusText: res.statusMessage,
            liveCallAttempted: true,
            headers: {
              'x-ms-ags-diagnostic': res.headers['x-ms-ags-diagnostic'] || null,
              'request-id': res.headers['request-id'] || null,
              'client-request-id': res.headers['client-request-id'] || null,
              'date': res.headers['date'] || null
            },
            data: resData ? (function() { try { return JSON.parse(resData); } catch { return resData; } })() : null
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 408, statusText: 'Request Timeout', liveCallAttempted: true, error: 'Connection timed out' });
    });

    req.on('error', err => {
      resolve({ status: 502, statusText: 'Bad Gateway', liveCallAttempted: true, error: err.message });
    });

    req.write(payload);
    req.end();
  });
}

async function dispatchPhysicalEmail({ recipient, subject, body, config = {} }) {
  const sendgridKey = config.sendgridApiKey || process.env.SENDGRID_API_KEY;
  const resendKey = config.resendApiKey || process.env.RESEND_API_KEY;
  const customFrom = config.fromEmail || process.env.EMAIL_FROM;

  if (resendKey) {
    return await sendViaResend({
      apiKey: resendKey,
      from: customFrom || 'onboarding@resend.dev',
      to: recipient,
      subject,
      body
    });
  }

  if (sendgridKey) {
    return await sendViaSendGrid({
      apiKey: sendgridKey,
      from: customFrom || 'azure-wif-agent@poc.internal',
      to: recipient,
      subject,
      body
    });
  }

  return {
    delivered: false,
    provider: 'unconfigured',
    notice: 'Real email dispatcher is armed. Set RESEND_API_KEY or SENDGRID_API_KEY in .env or via Web UI to deliver to ' + recipient,
    targetRecipient: recipient,
    dispatchedAt: new Date().toISOString()
  };
}

function sendViaResend({ apiKey, from, to, subject, body }) {
  return new Promise(resolve => {
    const payload = JSON.stringify({ from, to: [to], subject, text: body });
    const req = https.request(
      'https://api.resend.com/emails',
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 6000
      },
      res => {
        let resData = '';
        res.on('data', chunk => (resData += chunk));
        res.on('end', () => {
          let parsed;
          try { parsed = JSON.parse(resData); } catch { parsed = { raw: resData }; }
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({
              delivered: true,
              provider: 'Resend',
              statusCode: res.statusCode,
              messageId: parsed.id,
              recipient: to,
              dispatchedAt: new Date().toISOString()
            });
          } else {
            resolve({
              delivered: false,
              provider: 'Resend',
              statusCode: res.statusCode,
              error: parsed.message || parsed.error || resData,
              recipient: to
            });
          }
        });
      }
    );

    req.on('timeout', () => { req.destroy(); resolve({ delivered: false, provider: 'Resend', error: 'Connection timed out' }); });
    req.on('error', err => resolve({ delivered: false, provider: 'Resend', error: err.message }));
    req.write(payload);
    req.end();
  });
}

function sendViaSendGrid({ apiKey, from, to, subject, body }) {
  return new Promise(resolve => {
    const payload = JSON.stringify({
      personalizations: [{ to: [{ email: to }] }],
      from: { email: from },
      subject,
      content: [{ type: 'text/plain', value: body }]
    });

    const req = https.request(
      'https://api.sendgrid.com/v3/mail/send',
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 6000
      },
      res => {
        let resData = '';
        res.on('data', chunk => (resData += chunk));
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            const messageId = res.headers['x-message-id'] || 'sg-' + Date.now();
            resolve({
              delivered: true,
              provider: 'SendGrid',
              statusCode: res.statusCode,
              messageId,
              recipient: to,
              dispatchedAt: new Date().toISOString()
            });
          } else {
            let parsed;
            try { parsed = JSON.parse(resData); } catch { parsed = { raw: resData }; }
            resolve({
              delivered: false,
              provider: 'SendGrid',
              statusCode: res.statusCode,
              error: parsed.errors?.[0]?.message || parsed.message || resData,
              recipient: to
            });
          }
        });
      }
    );

    req.on('timeout', () => { req.destroy(); resolve({ delivered: false, provider: 'SendGrid', error: 'Connection timed out' }); });
    req.on('error', err => resolve({ delivered: false, provider: 'SendGrid', error: err.message }));
    req.write(payload);
    req.end();
  });
}

module.exports = {
  dispatchGraphEmail,
  callLiveMicrosoftGraphApi,
  dispatchPhysicalEmail
};
