# IP Address Tracking Feature

## Overview

The Script Integrity Monitor now tracks the IP address of clients that register scripts. This feature provides enhanced security auditing by recording which client IP addresses are submitting scripts for approval.

**Key Principle**: IP addresses are **only stored for non-approved scripts** and are automatically cleared when a script is approved.

## Feature Specifications

### When IP Addresses Are Tracked

✅ **IP is recorded when:**
- A new script is registered for the first time
- An existing non-approved script is re-registered
- Script status is: `pending_approval`, `rejected`, or `flagged`

❌ **IP is NOT recorded when:**
- Script is already approved (`approved` or `auto_approved` status)
- Script registration is re-detected after approval

### Automatic IP Clearing

IP addresses are automatically cleared (set to NULL) when:
- An administrator approves a script
- Status changes from any state to `approved`

**Rationale**: Approved scripts are legitimate and don't require client tracking. This reduces privacy concerns and data retention requirements.

## Database Schema

### New Columns Added to `scripts` Table

```sql
-- Registration Tracking
last_registered_ip TEXT,        -- IP address of client that last registered this script
last_registered_at DATETIME,    -- When script was last registered (for non-approved scripts)
```

These columns are:
- **NULL for approved scripts** (privacy-friendly)
- **Populated for pending/rejected scripts** (security auditing)
- **Updated on each registration** for non-approved scripts

## How It Works

### 1. Script Registration Flow

```
Client Request → Extract IP Address → Check Script Status
    ↓
If NOT approved:
    - Store IP in last_registered_ip
    - Update last_registered_at timestamp
    ↓
If approved:
    - Skip IP tracking
    - Only update access counters
```

### 2. IP Address Extraction

The server extracts the client IP from multiple sources (in priority order):

```javascript
const clientIp =
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||  // Proxy/Load Balancer
    req.headers['x-real-ip'] ||                               // Nginx
    req.socket.remoteAddress ||                               // Direct connection
    req.connection.remoteAddress;                             // Fallback
```

**Supports**:
- Direct connections
- Proxy headers (X-Forwarded-For)
- Nginx Real IP
- Load balancers

### 3. Approval Flow

```
Admin Approves Script → Update Status to 'approved'
    ↓
Automatically clear:
    - last_registered_ip → NULL
    - last_registered_at → NULL
    ↓
Privacy-friendly: No client data stored for approved scripts
```

## Admin Panel Display

### Script Inventory Table

The inventory now includes a **"Last Registered IP"** column:

| ID | URL | Type | Status | Access Count | **Last Registered IP** | Variation | First Seen | Approved By |
|----|-----|------|--------|--------------|----------------------|-----------|------------|-------------|
| 1  | script.js | external | **pending** | 5 | **192.168.1.100** | - | 2025-01-14 | - |
| 2  | tracker.js | external | **approved** | 12 | **-** | - | 2025-01-13 | admin |
| 3  | inline-0 | inline | **rejected** | 3 | **10.0.0.50** | - | 2025-01-14 | admin |

**Display Rules:**
- ✅ **Shows IP** for: `pending_approval`, `rejected`, `flagged` status
- ❌ **Shows "-"** for: `approved`, `auto_approved` status
- 🕐 **Tooltip** shows "Last registered: [timestamp]" on hover

### Visual Design

```html
<!-- For non-approved scripts with IP -->
<span style="font-family: monospace; font-size: 11px;"
      title="Last registered: 2025-01-14 10:30:15 AM">
    192.168.1.100
</span>

<!-- For approved scripts or no IP -->
<span style="color: #95a5a6;">-</span>
```

## Security & Privacy Considerations

### Privacy-Friendly Design

1. **Minimal Retention**: IPs only stored for scripts under review
2. **Automatic Deletion**: Cleared immediately upon approval
3. **Purpose-Specific**: Only for security auditing of unapproved scripts
4. **No User Correlation**: IPs not linked to user accounts

### IP Address Hashing (Optional)

While not currently implemented, the system supports IP hashing:

```javascript
// Optional: Hash IP addresses for privacy
const crypto = require('crypto');
const hashedIp = crypto.createHash('sha256')
    .update(clientIp + process.env.IP_SALT)
    .digest('hex');
```

**To enable IP hashing**:
1. Add `IP_SALT` to `.env`
2. Update `server-alert-handler.js` line 695-698
3. Hash IPs before storage

### Compliance Considerations

#### GDPR (EU)
- ✅ **Minimal data**: Only stores IPs for security purposes
- ✅ **Limited retention**: Auto-deleted on approval
- ✅ **Legitimate interest**: Security auditing and fraud prevention

#### CCPA (California)
- ✅ **Business purpose**: Security monitoring
- ✅ **Limited collection**: Only for unapproved scripts
- ✅ **No sale**: Data not shared or sold

## API Changes

### POST /api/scripts/register

**Request** (no changes - IP extracted from headers):
```json
{
  "url": "https://cdn.example.com/script.js",
  "contentHash": "sha384-abc123...",
  "scriptType": "external",
  "pageUrl": "https://example.com/checkout"
}
```

**Server Processing** (new):
```javascript
// Extract client IP
const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() ||
                 req.headers['x-real-ip'] ||
                 req.socket.remoteAddress;

// Pass to registration
await db.registerScript({
    url,
    contentHash,
    scriptType,
    pageUrl,
    clientIp  // NEW
});
```

**Database Update**:
```sql
-- If script is NOT approved
UPDATE scripts SET
    last_registered_ip = '192.168.1.100',
    last_registered_at = CURRENT_TIMESTAMP,
    access_count = access_count + 1
WHERE id = ?

-- If script IS approved
UPDATE scripts SET
    access_count = access_count + 1
    -- IP fields NOT updated
WHERE id = ?
```

### PUT /api/admin/scripts/:id/approve

**New Behavior**: Automatically clears IP when approving

```sql
UPDATE scripts SET
    status = 'approved',
    approved_by = ?,
    approved_at = CURRENT_TIMESTAMP,
    business_justification = ?,
    script_purpose = ?,
    script_owner = ?,
    risk_level = ?,
    approval_notes = ?,
    last_registered_ip = NULL,      -- NEW: Clear IP
    last_registered_at = NULL        -- NEW: Clear timestamp
WHERE id = ?
```

## Use Cases

### 1. Identifying Malicious Script Sources

**Scenario**: Same malicious script registered from multiple IPs

```sql
SELECT url, content_hash, last_registered_ip, last_registered_at
FROM scripts
WHERE status = 'pending_approval'
    AND url LIKE '%malicious%'
ORDER BY last_registered_at DESC;
```

**Result**: Track where attacks are originating

### 2. Detecting Repeated Submissions

**Scenario**: Same IP repeatedly registering rejected scripts

```sql
SELECT last_registered_ip, COUNT(*) as submission_count
FROM scripts
WHERE status = 'rejected'
    AND last_registered_ip IS NOT NULL
GROUP BY last_registered_ip
HAVING COUNT(*) > 5
ORDER BY submission_count DESC;
```

**Action**: Potential IP blocking or rate limiting

### 3. Auditing Script Origin

**Scenario**: Investigate where a suspicious script came from

```sql
SELECT id, url, status, last_registered_ip,
       last_registered_at, first_seen, page_url
FROM scripts
WHERE url = 'https://suspicious-cdn.com/script.js';
```

**Provides**: Complete audit trail for security investigation

### 4. Compliance Reporting

**Scenario**: Generate monthly report of script registrations

```sql
SELECT
    DATE(first_seen) as date,
    COUNT(*) as total_scripts,
    COUNT(DISTINCT last_registered_ip) as unique_ips,
    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
FROM scripts
WHERE first_seen >= DATE('now', '-30 days')
GROUP BY DATE(first_seen)
ORDER BY date DESC;
```

## Testing

### Manual Testing Steps

1. **Test IP Recording on New Script**:
   ```
   - Open test page: http://localhost:3000/test-script-blocking.html
   - Wait for scripts to register
   - Open admin panel → Script Inventory
   - Verify IP addresses appear in "Last Registered IP" column for pending scripts
   ```

2. **Test IP Clearing on Approval**:
   ```
   - Find a pending script with IP address
   - Click to view details (note the IP)
   - Approve the script
   - Refresh Script Inventory
   - Verify IP column now shows "-" for that script
   ```

3. **Test IP Update on Re-Registration**:
   ```
   - Note a pending script's IP
   - Reload the test page (re-register scripts)
   - Refresh Script Inventory
   - Verify timestamp updated (IP may change if different client)
   ```

4. **Test Approved Script Doesn't Update IP**:
   ```
   - Approve a script (IP should clear)
   - Reload test page (re-register scripts)
   - Refresh Script Inventory
   - Verify approved script still shows "-" (no new IP stored)
   ```

### Database Verification

```sql
-- Check IP tracking is working
SELECT id, url, status, last_registered_ip, last_registered_at
FROM scripts
WHERE status != 'approved'
ORDER BY last_registered_at DESC
LIMIT 10;

-- Verify approved scripts have no IP
SELECT id, url, status, last_registered_ip
FROM scripts
WHERE status = 'approved';
-- Should show all NULL for last_registered_ip
```

## Configuration

### Environment Variables

No new environment variables required. However, for IP hashing (optional):

```bash
# .env
IP_SALT=your-random-salt-here-change-in-production
```

### Nginx Configuration (Production)

Ensure Real IP is passed to Node.js:

```nginx
location / {
    proxy_pass http://localhost:3000;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Host $host;
}
```

## Limitations

### Known Limitations

1. **No Historical IPs**: Only stores the *last* registration IP
   - **Workaround**: Add `ip_history` table for full tracking

2. **Proxy Spoofing**: X-Forwarded-For can be spoofed
   - **Mitigation**: Use trusted proxy headers only
   - **Solution**: Validate proxy IPs, use X-Real-IP from trusted sources

3. **NAT/Corporate Networks**: Multiple users may share one IP
   - **Impact**: Can't distinguish individual users
   - **Acceptable**: Security auditing at network level

4. **IPv6 Privacy Extensions**: IPv6 addresses may rotate
   - **Impact**: Same client may appear as different IPs
   - **Acceptable**: Still useful for correlation

## Future Enhancements

### Planned Improvements

1. **IP History Table**
   ```sql
   CREATE TABLE script_registration_history (
       id INTEGER PRIMARY KEY,
       script_id INTEGER,
       ip_address TEXT,
       registered_at DATETIME,
       user_agent TEXT,
       page_url TEXT
   );
   ```

2. **Geolocation Lookup**
   - Integrate with MaxMind GeoIP
   - Display country/city in admin panel

3. **IP Reputation Scoring**
   - Check against known bad IP lists
   - Auto-flag scripts from suspicious IPs

4. **Rate Limiting by IP**
   - Track registration attempts per IP
   - Auto-block abusive IPs

5. **Export IP Reports**
   - CSV export with IP data
   - Security incident reports

## Summary

The IP tracking feature enhances security by:

✅ **Recording client IPs** for unapproved scripts
✅ **Automatic privacy protection** by clearing IPs on approval
✅ **Admin visibility** in the Script Inventory
✅ **Security auditing** for suspicious script origins
✅ **Compliance-friendly** with minimal data retention

**Access**: http://localhost:3000/admin-panel.html → **Script Inventory** tab

The "Last Registered IP" column shows IP addresses only for non-approved scripts, providing security visibility while respecting privacy for approved content.
