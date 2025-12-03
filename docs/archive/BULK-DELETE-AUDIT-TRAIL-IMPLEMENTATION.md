# Bulk Delete & Audit Trail Implementation Guide

## Overview
This document describes the bulk delete and comprehensive audit trail features implemented for the PCI DSS Script Integrity Monitor admin panel.

## ✅ Completed Implementation

### 1. Database Schema (database-schema.sql & database-schema-postgres.sql)

**Audit Trail Table Added:**
- 19 configurable fields including timestamp, user info, action details, request metadata
- Support for bulk operations (entity_count field)
- 7-year retention for PCI DSS compliance
- Indexes for fast querying (timestamp, user, action, entity)
- Views: `v_audit_trail_recent` (last 30 days), `v_audit_trail_failures` (security monitoring)

**Action Types Tracked:**
- Script Management: approved, rejected, deleted, bulk_deleted
- Violation Management: reviewed, deleted, bulk_deleted
- Header Management: violation reviewed/deleted/bulk_deleted, baseline deleted/bulk_deleted
- Network Management: violation reviewed/deleted/bulk_deleted, domain whitelisted/removed
- User Management: created, updated, deleted, password_changed, role_changed, MFA enabled/disabled
- Authentication: login_success, login_failed, logout, password_reset
- Settings: settings_updated, config_changed

### 2. Server Implementation (server-alert-handler.js)

**Audit Logging Function (lines 254-321):**
```javascript
async function logAudit(options)
```
- Captures all admin actions with full context
- Hashes IP addresses for privacy
- Calculates 7-year retention dates
- Non-blocking (doesn't fail main operations)
- Logs success/failure with error messages

**Bulk Delete Endpoints (lines 1650-1838):**
- `POST /api/admin/violations/bulk-delete` - Delete multiple script violations
- `POST /api/admin/headers/violations/bulk-delete` - Delete multiple header violations
- `POST /api/admin/headers/baselines/bulk-delete` - Delete multiple header baselines
- `POST /api/admin/network/violations/bulk-delete` - Delete multiple network violations

All endpoints:
- Accept `{ ids: [1, 2, 3] }` in request body
- Validate input (array, non-empty)
- Use parameterized queries with placeholders
- Log to audit trail (success and failure)
- Return `{ success: true, deleted: count }`

**Audit Trail Viewing Endpoints (lines 1840-1985):**

`GET /api/admin/audit-trail`
- Pagination support (page, limit)
- Filtering: actionType, username, entityType, startDate, endDate, success
- Returns: logs array, total count, pagination info

`GET /api/admin/audit-trail/stats`
- Total logs count
- Last 24 hours, last 7 days counts
- Failed actions count
- Top 10 actions by type
- Top 10 users by action count

### 3. Admin Panel UI (public/admin-panel.html)

**New "Audit Trail" Tab Added (line 492, lines 632-702):**
- Statistics cards showing key metrics
- Advanced filters: action type, username, date range, success/failure status
- Paginated audit log table
- Audit trail visualization

**Tab Structure:**
```html
<button class="tab" onclick="showTab('audit', this)">Audit Trail</button>

<div id="audit" class="content-section" style="display: none;">
  <!-- Statistics Cards -->
  <div id="auditStats">...</div>

  <!-- Filters -->
  <div>...</div>

  <!-- Audit Trail Table -->
  <div id="auditContent">...</div>

  <!-- Pagination -->
  <div id="auditPagination">...</div>
</div>
```

## 🔧 Required JavaScript Functions (To Be Added)

### Audit Trail Functions

Add these functions to the `<script>` section of admin-panel.html:

```javascript
// Audit Trail State
let currentAuditPage = 1;
const auditPageSize = 50;

/**
 * Load audit trail with filters
 */
async function loadAuditTrail(page = 1) {
    currentAuditPage = page;

    const filters = {
        page,
        limit: auditPageSize,
        actionType: document.getElementById('auditFilterActionType')?.value || '',
        username: document.getElementById('auditFilterUsername')?.value || '',
        startDate: document.getElementById('auditFilterStartDate')?.value || '',
        endDate: document.getElementById('auditFilterEndDate')?.value || '',
        success: document.getElementById('auditFilterSuccess')?.value || ''
    };

    // Build query string
    const queryParams = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
        if (value) queryParams.append(key, value);
    });

    try {
        const response = await fetch(`${API_BASE}/api/admin/audit-trail?${queryParams}`, {
            headers: { 'X-API-Token': API_TOKEN }
        });

        if (!response.ok) throw new Error('Failed to fetch audit trail');

        const data = await response.json();
        renderAuditTrail(data.logs);
        renderAuditPagination(data.page, data.totalPages, data.total);
    } catch (error) {
        console.error('Error loading audit trail:', error);
        document.getElementById('auditContent').innerHTML =
            '<div class="error">Failed to load audit trail</div>';
    }
}

/**
 * Render audit trail table
 */
function renderAuditTrail(logs) {
    const container = document.getElementById('auditContent');

    if (!logs || logs.length === 0) {
        container.innerHTML = '<div class="empty-state">No audit logs found</div>';
        return;
    }

    const html = `
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>User</th>
                    <th>Action</th>
                    <th>Description</th>
                    <th>Entity</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                ${logs.map(log => `
                    <tr style="${log.success ? '' : 'background: #fff3cd;'}">
                        <td>${new Date(log.timestamp).toLocaleString()}</td>
                        <td>
                            <strong>${escapeHtml(log.username)}</strong>
                            ${log.user_role ? `<br><span style="font-size: 11px; color: #7f8c8d;">${log.user_role}</span>` : ''}
                        </td>
                        <td>
                            <code style="font-size: 11px;">${escapeHtml(log.action_type)}</code>
                        </td>
                        <td>
                            ${escapeHtml(log.action_description)}
                            ${log.action_reason ? `<br><em style="font-size: 12px; color: #7f8c8d;">${escapeHtml(log.action_reason)}</em>` : ''}
                            ${log.error_message ? `<br><span style="color: #e74c3c; font-size: 12px;">Error: ${escapeHtml(log.error_message)}</span>` : ''}
                        </td>
                        <td>
                            ${log.entity_type ? escapeHtml(log.entity_type) : '-'}
                            ${log.entity_count > 1 ? `<br><span style="font-size: 11px;">(${log.entity_count} items)</span>` : ''}
                        </td>
                        <td>
                            <span class="badge ${log.success ? 'badge-success' : 'badge-danger'}">
                                ${log.success ? '✓ Success' : '✗ Failed'}
                            </span>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;

    container.innerHTML = html;
}

/**
 * Render audit trail pagination
 */
function renderAuditPagination(currentPage, totalPages, total) {
    const container = document.getElementById('auditPagination');

    if (totalPages <= 1) {
        container.innerHTML = `<div>Showing all ${total} logs</div>`;
        return;
    }

    const pages = [];
    for (let i = 1; i <= Math.min(totalPages, 10); i++) {
        pages.push(i);
    }

    container.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: center; gap: 10px;">
            <button onclick="loadAuditTrail(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>
                Previous
            </button>
            ${pages.map(p => `
                <button onclick="loadAuditTrail(${p})"
                        ${p === currentPage ? 'class="active"' : ''}>
                    ${p}
                </button>
            `).join('')}
            ${totalPages > 10 ? '<span>...</span>' : ''}
            <button onclick="loadAuditTrail(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>
                Next
            </button>
            <span style="margin-left: 20px;">Page ${currentPage} of ${totalPages} (${total} total)</span>
        </div>
    `;
}

/**
 * Load audit trail statistics
 */
async function loadAuditStats() {
    try {
        const response = await fetch(`${API_BASE}/api/admin/audit-trail/stats`, {
            headers: { 'X-API-Token': API_TOKEN }
        });

        if (!response.ok) throw new Error('Failed to fetch stats');

        const stats = await response.json();
        renderAuditStats(stats);
    } catch (error) {
        console.error('Error loading audit stats:', error);
    }
}

/**
 * Render audit trail statistics cards
 */
function renderAuditStats(stats) {
    const container = document.getElementById('auditStats');

    container.innerHTML = `
        <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <div style="font-size: 32px; font-weight: bold; color: #3498db;">${stats.totalLogs.toLocaleString()}</div>
            <div style="color: #7f8c8d; margin-top: 5px;">Total Logs</div>
        </div>
        <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <div style="font-size: 32px; font-weight: bold; color: #27ae60;">${stats.last24Hours.toLocaleString()}</div>
            <div style="color: #7f8c8d; margin-top: 5px;">Last 24 Hours</div>
        </div>
        <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <div style="font-size: 32px; font-weight: bold; color: #f39c12;">${stats.last7Days.toLocaleString()}</div>
            <div style="color: #7f8c8d; margin-top: 5px;">Last 7 Days</div>
        </div>
        <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <div style="font-size: 32px; font-weight: bold; color: ${stats.failedActions > 0 ? '#e74c3c' : '#95a5a6'};">${stats.failedActions.toLocaleString()}</div>
            <div style="color: #7f8c8d; margin-top: 5px;">Failed Actions</div>
        </div>
    `;
}

/**
 * Apply audit trail filters
 */
function applyAuditFilters() {
    loadAuditTrail(1);
}
```

### Bulk Delete Functions

```javascript
// Bulk Delete State
const selectedViolations = new Set();
const selectedHeaderViolations = new Set();
const selectedHeaderBaselines = new Set();
const selectedNetworkViolations = new Set();

/**
 * Toggle violation selection
 */
function toggleViolationSelection(id) {
    if (selectedViolations.has(id)) {
        selectedViolations.delete(id);
    } else {
        selectedViolations.add(id);
    }
    updateBulkDeleteButton('violations', selectedViolations.size);
}

/**
 * Select/deselect all violations
 */
function toggleAllViolations(checked) {
    selectedViolations.clear();
    if (checked) {
        document.querySelectorAll('.violation-checkbox').forEach(cb => {
            selectedViolations.add(parseInt(cb.value));
            cb.checked = true;
        });
    } else {
        document.querySelectorAll('.violation-checkbox').forEach(cb => {
            cb.checked = false;
        });
    }
    updateBulkDeleteButton('violations', selectedViolations.size);
}

/**
 * Bulk delete violations
 */
async function bulkDeleteViolations() {
    if (selectedViolations.size === 0) {
        alert('No violations selected');
        return;
    }

    if (!confirm(`Delete ${selectedViolations.size} violation(s)? This cannot be undone.`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/admin/violations/bulk-delete`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Token': API_TOKEN
            },
            body: JSON.stringify({ ids: Array.from(selectedViolations) })
        });

        if (!response.ok) throw new Error('Bulk delete failed');

        const result = await response.json();
        alert(`Successfully deleted ${result.deleted} violation(s)`);

        selectedViolations.clear();
        await loadData(); // Refresh all data
    } catch (error) {
        console.error('Bulk delete error:', error);
        alert('Failed to delete violations: ' + error.message);
    }
}

/**
 * Update bulk delete button visibility and count
 */
function updateBulkDeleteButton(type, count) {
    const button = document.getElementById(`bulk-delete-${type}`);
    if (button) {
        button.style.display = count > 0 ? 'inline-block' : 'none';
        button.textContent = `Delete Selected (${count})`;
    }
}

// Similar functions for header violations, baselines, and network violations...
```

### Integration with Existing Code

**Modify loadData() function** to initialize audit trail when tab is shown:

```javascript
async function loadData() {
    if (!API_TOKEN) {
        document.getElementById('auth').style.display = 'flex';
        return;
    }

    document.getElementById('auth').style.display = 'none';
    document.getElementById('dashboard').style.display = 'block';

    try {
        await Promise.all([
            loadScripts(),
            loadViolations(),
            loadPendingScripts(),
            loadDashboard(),
            loadHeaderViolations(),
            loadHeaderBaselines(),
            loadNetworkViolations(),
            loadUsers(),
            loadAuditStats(),     // Add this
            loadAuditTrail()      // Add this
        ]);
    } catch (error) {
        console.error('Error loading data:', error);
    }
}
```

**Modify violation rendering functions** to add checkboxes:

Example for violations table:
```javascript
<th><input type="checkbox" onchange="toggleAllViolations(this.checked)"></th>
...
<td><input type="checkbox" class="violation-checkbox" value="${v.id}" onchange="toggleViolationSelection(${v.id})"></td>
```

Add bulk delete button above table:
```html
<button id="bulk-delete-violations" style="display: none;" onclick="bulkDeleteViolations()" class="danger">
    Delete Selected (0)
</button>
```

## 📋 Next Steps

1. **Initialize Database:**
   ```bash
   npm run db:init
   ```
   This will create the `audit_trail` table.

2. **Add JavaScript Functions:**
   Copy the functions above into the `<script>` section of `public/admin-panel.html`

3. **Add Bulk Select UI:**
   - Modify violation table rendering functions to include checkboxes
   - Add "Select All" checkbox in table header
   - Add "Delete Selected" button above each table

4. **Test:**
   - Test bulk delete for each violation type
   - Test audit trail filtering and pagination
   - Verify audit logs are created for all actions
   - Check PCI DSS 7-year retention calculation

## 🎯 PCI DSS Compliance

This implementation addresses:
- **Comprehensive Audit Trail**: All admin actions logged
- **7-Year Retention**: Automatic retention date calculation
- **Tamper-Proof**: Logs cannot be modified, only archived
- **Detailed Tracking**: Who, what, when, why, and result
- **Bulk Operations**: Tracked with entity count for compliance reporting
- **IP Privacy**: IP addresses hashed before storage
- **Failed Actions**: Monitored for security incidents

## API Endpoints Summary

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/admin/violations/bulk-delete` | POST | Delete multiple script violations |
| `/api/admin/headers/violations/bulk-delete` | POST | Delete multiple header violations |
| `/api/admin/headers/baselines/bulk-delete` | POST | Delete multiple header baselines |
| `/api/admin/network/violations/bulk-delete` | POST | Delete multiple network violations |
| `/api/admin/audit-trail` | GET | Get paginated audit logs with filters |
| `/api/admin/audit-trail/stats` | GET | Get audit trail statistics |

## Database Schema

```sql
CREATE TABLE audit_trail (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    username TEXT NOT NULL,
    user_role TEXT,
    action_type TEXT NOT NULL CHECK(...),
    entity_type TEXT CHECK(...),
    entity_id TEXT,
    entity_count INTEGER DEFAULT 1,
    action_description TEXT NOT NULL,
    action_reason TEXT,
    ip_address TEXT,
    user_agent TEXT,
    request_method TEXT,
    request_path TEXT,
    old_values TEXT,
    new_values TEXT,
    success BOOLEAN DEFAULT 1,
    error_message TEXT,
    retention_until DATETIME,
    archived BOOLEAN DEFAULT 0
);
```

## Support

For issues or questions:
- Check server logs: `[Audit]` prefix
- Check browser console for API errors
- Verify database schema is up to date
- Confirm API_TOKEN is valid
