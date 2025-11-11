# Script Integrity Monitoring - Approval Workflow

## Overview

This document describes the automatic file detection and server-side approval workflow for the enhanced PCI DSS v4.0 Script Integrity Monitoring solution.

## Table of Contents

1. [Workflow Overview](#workflow-overview)
2. [Client-Side Auto-Detection](#client-side-auto-detection)
3. [Server-Side Registration](#server-side-registration)
4. [Admin Approval Process](#admin-approval-process)
5. [Integration Guide](#integration-guide)
6. [API Reference](#api-reference)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)

---

## Workflow Overview

The approval workflow consists of four main stages:

```
┌─────────────────────────────────────────────────────────────────┐
│                    1. SCRIPT DETECTION                          │
│  Browser detects script → Calculate hash → Check baseline       │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    2. AUTO-REGISTRATION                         │
│  New script? → POST to /api/scripts/register → Queue approval   │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    3. ADMIN REVIEW                              │
│  Admin logs in → Reviews script → Approves/Rejects             │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    4. STATUS UPDATE                             │
│  Client polls status → Update approved → Allow execution        │
└─────────────────────────────────────────────────────────────────┘
```

### Script States

Scripts can be in one of the following states:

| State | Description | Client Behavior |
|-------|-------------|-----------------|
| `NEW_SCRIPT` | First time detected, not yet registered | Auto-register with server |
| `pending_approval` | Registered but awaiting admin approval | Report mode, poll for updates |
| `approved` | Admin has approved the script | Allow execution |
| `rejected` | Admin has rejected the script | Block/alert based on mode |
| `flagged` | Marked for investigation | Block/alert based on mode |

---

## Client-Side Auto-Detection

### How It Works

The enhanced `script-integrity-monitor.js` automatically:

1. **Detects ALL scripts** on page load and dynamically added
2. **Calculates SHA-384 hash** of each script's content
3. **Categorizes scripts** into three types:
   - **NEW**: Never seen before (no baseline, not on server)
   - **KNOWN-CHANGED**: In baseline but hash mismatch
   - **APPROVED**: Valid hash or server-approved

### Detection Flow

```javascript
// Pseudo-code for detection logic
async function processScript(script) {
  // Step 1: Calculate hash
  const hash = await calculateHash(script.content);

  // Step 2: Check baseline configuration
  const baselineHash = config.baselineHashes[script.url];

  if (baselineHash) {
    // KNOWN SCRIPT
    if (hash === baselineHash) {
      return { status: 'APPROVED', action: 'allow' };
    } else {
      // INTEGRITY VIOLATION
      reportViolation({ type: 'HASH_MISMATCH', script, hash });
      return { status: 'VIOLATED', action: 'block/report' };
    }
  }

  // Step 3: Check server status
  const serverStatus = await checkScriptStatus(hash);

  if (serverStatus) {
    return { status: serverStatus.status, action: 'from-server' };
  }

  // Step 4: NEW SCRIPT - Auto-register
  await registerNewScript(script, hash);
  return { status: 'PENDING_APPROVAL', action: 'report' };
}
```

### Configuration

Enable auto-detection in `script-integrity-config.js`:

```javascript
window.SCRIPT_INTEGRITY_CONFIG = {
  // Server configuration
  serverBaseUrl: 'https://your-domain.com',
  autoRegisterNewScripts: true,  // Enable auto-registration

  // Polling configuration
  pollApprovalStatus: true,      // Poll for approval updates
  pollInterval: 30000,           // Check every 30 seconds
  pollTimeout: 300000,           // Stop after 5 minutes

  // Fallback behavior
  fallbackMode: 'report',        // 'report' or 'block' if server unreachable
  serverTimeoutMs: 5000,

  // Baseline hashes (known approved scripts)
  baselineHashes: {
    'https://cdn.example.com/jquery.js': 'sha384-...'
  }
};
```

---

## Server-Side Registration

### Registration Process

When a new script is detected:

1. **Client sends POST request** to `/api/scripts/register`
2. **Server validates** the request
3. **Database stores** script metadata
4. **Deduplication check** prevents duplicate entries
5. **Notification queued** for admin team
6. **Response sent** to client with script status

### Registration Payload

```javascript
POST /api/scripts/register
Content-Type: application/json
X-Session-ID: session-abc123

{
  "url": "https://example.com/script.js",
  "contentHash": "sha384-abcd1234...",
  "scriptType": "external",  // or "inline"
  "sizeBytes": 15420,
  "contentPreview": "/* Script content first 500 chars... */",
  "pageUrl": "https://example.com/checkout",
  "discoveryContext": "{\"loadType\":\"initial-load\",\"timestamp\":1699887654321}"
}
```

### Server Response

```javascript
{
  "success": true,
  "scriptId": 42,
  "status": "pending_approval",  // or "approved" if already known
  "isNew": true
}
```

### Database Storage

Scripts are stored in the `scripts` table with:
- URL and content hash
- Discovery metadata (page, timestamp)
- Approval status
- Business justification (after approval)
- Audit trail

---

## Admin Approval Process

### Accessing the Admin Panel

1. **Navigate to** `http://your-server:3000/admin-panel.html`
2. **Enter API token** (default: `demo-token-12345`)
3. **View dashboard** with statistics and pending scripts

### Approval Workflow

#### 1. Review Pending Scripts

The admin panel shows:
- **Script URL** and hash
- **Discovery details** (when/where found)
- **Content preview** (first 500 characters)
- **Script type** (inline/external)
- **Occurrence count** (how many times seen)

#### 2. Approve a Script

Required information:
- **Business Justification** (why this script is needed)
- **Script Purpose** (what the script does)
- **Script Owner** (optional - who maintains it)
- **Risk Level** (low/medium/high/critical)
- **Notes** (optional additional context)

**Example Approval:**

```
Business Justification: "Required for payment processing via Stripe Checkout"
Script Purpose: "Stripe.js library for secure credit card tokenization"
Script Owner: "Payment Team"
Risk Level: Medium
Notes: "Stripe is a PCI DSS Level 1 certified service provider"
```

#### 3. Reject a Script

Required information:
- **Rejection Reason** (why script is being rejected)
- **Notes** (optional additional context)

**Example Rejection:**

```
Rejection Reason: "Unauthorized third-party tracking script"
Notes: "Script does not comply with privacy policy. Requesting removal."
```

### API Endpoints for Approval

#### Approve Script
```bash
POST /api/admin/scripts/:id/approve
X-API-Token: your-token

{
  "businessJustification": "Required for...",
  "scriptPurpose": "Handles...",
  "scriptOwner": "Team Name",
  "riskLevel": "medium",
  "approvalNotes": "Additional context..."
}
```

#### Reject Script
```bash
POST /api/admin/scripts/:id/reject
X-API-Token: your-token

{
  "rejectionReason": "Unauthorized script",
  "notes": "Additional context..."
}
```

### Audit Trail

All approval actions are logged in `approval_audit_log` table:
- Who approved/rejected (admin username)
- When (timestamp)
- Why (reason/justification)
- Previous and new status
- IP address and user agent

---

## Integration Guide

### Step 1: Install Dependencies

```bash
cd /path/to/jscrambler
npm install
```

### Step 2: Configure Environment

Create `.env` file:

```env
# Database Configuration
DB_TYPE=sqlite
SQLITE_PATH=./data/integrity-monitor.db

# For PostgreSQL (production):
# DB_TYPE=postgres
# PG_HOST=localhost
# PG_PORT=5432
# PG_DATABASE=script_integrity
# PG_USER=postgres
# PG_PASSWORD=your_password

# Server Configuration
PORT=3000
NODE_ENV=development

# Security
CORS_ORIGIN=*
IP_SALT=random-salt-change-in-production

# Logging
LOG_QUERIES=false
```

### Step 3: Initialize Database

```bash
npm run db:init
```

This will:
- Create database file (if SQLite)
- Run migrations
- Create tables
- Insert default configuration

### Step 4: Start Server

```bash
# Development
npm run dev

# Production
npm start
```

### Step 5: Integrate Client-Side

Add to your HTML pages:

```html
<!DOCTYPE html>
<html>
<head>
  <!-- CRITICAL: Load configuration FIRST -->
  <script src="/js/script-integrity-config.js"></script>

  <!-- CRITICAL: Load monitor SECOND (before other scripts) -->
  <script src="/js/script-integrity-monitor.js"></script>

  <!-- Other scripts will be monitored -->
  <script src="https://cdn.example.com/library.js"></script>
</head>
<body>
  <!-- Your content -->
</body>
</html>
```

### Step 6: Configure Server Endpoints

In `script-integrity-config.js`, set `serverBaseUrl`:

```javascript
// Development
if (hostname === 'localhost' || hostname === '127.0.0.1') {
  config.serverBaseUrl = 'http://localhost:3000';
}

// Production
else if (hostname === 'your-domain.com') {
  config.serverBaseUrl = 'https://your-domain.com';
}
```

---

## API Reference

### Public Endpoints (No Authentication)

#### Register New Script
```
POST /api/scripts/register
Rate Limit: 200 requests/hour per session
```

#### Check Script Status
```
GET /api/scripts/status/:hash
Rate Limit: 100 requests/15 minutes
```

#### Report Violation
```
POST /api/scripts/violation
Rate Limit: 100 requests/15 minutes per session
```

### Admin Endpoints (Authentication Required)

All admin endpoints require `X-API-Token` header.

#### Get Dashboard Statistics
```
GET /api/admin/dashboard
```

#### Get Pending Approvals
```
GET /api/admin/scripts/pending?limit=50&offset=0
```

#### Approve Script
```
POST /api/admin/scripts/:id/approve
```

#### Reject Script
```
POST /api/admin/scripts/:id/reject
```

#### Get Violations
```
GET /api/admin/violations?limit=50&offset=0
```

#### Search Scripts
```
GET /api/admin/scripts/search?q=keyword&status=approved&type=external
```

#### Update Violation Review
```
POST /api/admin/violations/:id/review
```

### Health Check
```
GET /health
```

---

## Security Considerations

### 1. Authentication

- **Admin endpoints** require API token authentication
- **Tokens stored** in `admin_users` table
- **Token transmitted** via `X-API-Token` header or `Authorization: Bearer` header
- **Never expose** tokens in client-side code

### 2. Rate Limiting

- **Per-session limits** prevent abuse
- **Different limits** for different endpoint types:
  - Registration: 200/hour per session
  - Violations: 100/15min per session
  - General: 100/15min per IP

### 3. Input Validation

- **All inputs sanitized** before database storage
- **Prepared statements** prevent SQL injection
- **Content-length limits** prevent DoS attacks

### 4. Privacy

- **IP addresses hashed** before storage
- **User sessions** anonymized with hashing
- **Compliance** with GDPR/privacy regulations

### 5. Database Security

- **Foreign key constraints** ensure referential integrity
- **Triggers** maintain audit trail
- **Transactions** ensure atomicity
- **Connection pooling** prevents exhaustion

### 6. PCI DSS Compliance

- **Complete audit trail** of all script approvals
- **Business justification** required (PCI 6.4.3)
- **7-year retention** of audit logs
- **Regular review** capability

---

## Troubleshooting

### Client-Side Issues

**Problem: Scripts not being auto-registered**

Solutions:
- Check `config.serverBaseUrl` is set correctly
- Check `config.autoRegisterNewScripts` is `true`
- Check browser console for errors
- Verify server is reachable (check `/health` endpoint)

**Problem: Polling not working**

Solutions:
- Check `config.pollApprovalStatus` is `true`
- Check browser console for polling errors
- Verify poll interval and timeout settings

**Problem: False positive violations**

Solutions:
- Check baseline hashes are correct
- Use `SCRIPT_INTEGRITY_CONFIG.generateBaselineHashes()` to regenerate
- Verify CDN scripts haven't been updated
- Check for dynamic script injection

### Server-Side Issues

**Problem: Database connection fails**

Solutions:
- Check database file path (SQLite)
- Verify PostgreSQL credentials
- Check file permissions
- Review database logs

**Problem: Admin login fails**

Solutions:
- Verify token exists in `admin_users` table
- Check token is active (`is_active = 1`)
- Verify account not locked (`locked_until`)
- Check server logs for auth errors

**Problem: Notifications not sending**

Solutions:
- Check `system_config` table for email settings
- Verify notification queue is being processed
- Check email service configuration
- Review notification logs

### Performance Issues

**Problem: High database load**

Solutions:
- Add indexes to frequently queried columns
- Implement connection pooling (PostgreSQL)
- Run cleanup scripts regularly
- Archive old records

**Problem: Slow admin panel**

Solutions:
- Implement pagination (limit/offset)
- Add caching layer (Redis)
- Optimize database queries
- Use database views for complex queries

---

## Best Practices

### 1. Initial Deployment

1. **Start in report mode** to avoid blocking legitimate scripts
2. **Generate baseline hashes** for all known scripts
3. **Monitor violations** for 1-2 weeks
4. **Review all pending** scripts before enforcing
5. **Gradually transition** to enforce mode

### 2. Ongoing Maintenance

1. **Review pending approvals** at least daily
2. **Investigate violations** within 24 hours
3. **Update baseline hashes** when scripts change
4. **Document all approvals** thoroughly
5. **Regular audits** of approved scripts (quarterly)

### 3. Change Management

When updating scripts:

1. **Generate new hash** for updated script
2. **Update baseline** in configuration
3. **Update business justification** if purpose changes
4. **Test in staging** before production
5. **Monitor for issues** after deployment

### 4. Incident Response

When violations occur:

1. **Immediate alert** for critical violations
2. **Investigate source** of unexpected scripts
3. **Block if malicious** (switch to enforce mode)
4. **Document incident** in review notes
5. **Update security controls** to prevent recurrence

---

## Example Workflows

### Workflow 1: Approving a New Payment Script

1. **Detection**: User visits checkout page, Stripe.js detected
2. **Registration**: Auto-registered as `pending_approval`
3. **Admin Review**:
   ```
   URL: https://js.stripe.com/v3/
   Hash: sha384-abc123...
   Purpose: Stripe.js payment processing
   Justification: Required for PCI-compliant payment processing
   Risk: Medium
   ```
4. **Approval**: Admin approves with justification
5. **Update**: Client polls, receives approved status
6. **Execution**: Script allowed to execute

### Workflow 2: Detecting Compromised Script

1. **Detection**: Known script hash doesn't match baseline
2. **Violation**: `HASH_MISMATCH` violation logged
3. **Alert**: High-severity alert sent to security team
4. **Investigation**: Admin reviews in violations tab
5. **Action**: If malicious, switch to enforce mode to block
6. **Resolution**: Update baseline if legitimate change, or remove script

### Workflow 3: Rejecting Unauthorized Tracker

1. **Detection**: New analytics script discovered
2. **Registration**: Auto-registered as `pending_approval`
3. **Admin Review**: Determines script is unauthorized
4. **Rejection**:
   ```
   Reason: Unauthorized third-party tracking
   Notes: Violates privacy policy. Not business-critical.
   ```
5. **Client Update**: Script marked as rejected
6. **Action**: Alert shown, script blocked in enforce mode

---

## Support and Maintenance

### Logging

All components log to console with prefixes:
- `[SIM]` - Client-side monitor
- `[DB]` - Database operations
- `[Server]` - Server operations
- `[Admin]` - Admin actions
- `[Auth]` - Authentication

### Database Maintenance

Run periodic cleanup:
```bash
node scripts/cleanup-old-records.js
```

This removes:
- Resolved violations older than 365 days
- Audit logs older than 7 years (PCI requirement)

### Monitoring

Monitor these metrics:
- Pending approval queue size
- Violation rate
- Response times
- Database size
- Error rates

---

## Compliance Checklist

- [ ] All scripts have documented business justification
- [ ] Approval process is followed for all new scripts
- [ ] Violations are reviewed within SLA
- [ ] Audit trail is maintained (7 years)
- [ ] Regular compliance reviews conducted
- [ ] Baseline hashes kept up to date
- [ ] Admin access is restricted and audited
- [ ] Incident response procedures documented

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0.0 | 2025-11-11 | Added auto-detection and approval workflow |
| 1.0.0 | 2025-11-01 | Initial release with basic monitoring |

---

## Additional Resources

- [PCI DSS v4.0 Requirement 6.4.3](https://www.pcisecuritystandards.org/)
- [Subresource Integrity (SRI)](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

---

**For support or questions, contact your security team or refer to the project documentation.**
