/**
 * Audit Trail Module
 * Handles audit log display, filtering, and statistics
 */

async function loadAuditTrail(page = 1) {
    currentAuditPage = page;

    const actionType = document.getElementById('auditFilterActionType').value;
    const username = document.getElementById('auditFilterUsername').value;
    const startDate = document.getElementById('auditFilterStartDate').value;
    const endDate = document.getElementById('auditFilterEndDate').value;
    const success = document.getElementById('auditFilterSuccess').value;

    // Build query parameters
    const params = new URLSearchParams({
        page: page,
        limit: auditPageSize
    });

    if (actionType) params.append('actionType', actionType);
    if (username) params.append('username', username);
    if (startDate) params.append('startDate', startDate);
    if (endDate) params.append('endDate', endDate);
    if (success) params.append('success', success);

    try {
        const data = await apiCall(`/api/admin/audit-trail?${params}`);
        //const data = await response.json();

        if (data.error) {
            document.getElementById('auditContent').innerHTML =
                `<div class="error-message">${escapeHtml(data.error)}</div>`;
            return;
        }

        renderAuditTrail(data);
        renderAuditPagination(data);
    } catch (error) {
        console.error('Failed to load audit trail:', error);
        document.getElementById('auditContent').innerHTML =
            '<div class="error-message">Failed to load audit trail</div>';
    }
}

/**
 * Render audit trail table
 */
function renderAuditTrail(data) {
    const container = document.getElementById('auditContent');

    if (!data.logs || data.logs.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #7f8c8d; padding: 40px;">No audit logs found for the selected filters.</p>';
        return;
    }

    let html = `
        <table>
            <thead>
                <tr>
                    <th style="width: 140px;">Timestamp</th>
                    <th style="width: 120px;">User</th>
                    <th style="width: 180px;">Action</th>
                    <th style="width: 100px;">Entity</th>
                    <th>Description</th>
                    <th style="width: 80px;">Status</th>
                </tr>
            </thead>
            <tbody>
    `;

    data.logs.forEach(log => {
        const timestamp = new Date(log.timestamp).toLocaleString();
        const statusBadge = log.success
            ? '<span class="badge badge-success">Success</span>'
            : '<span class="badge badge-danger">Failed</span>';

        const actionBadge = getActionBadge(log.action_type);

        html += `
            <tr>
                <td style="font-size: 12px;">${escapeHtml(timestamp)}</td>
                <td><strong>${escapeHtml(log.username)}</strong></td>
                <td>${actionBadge}</td>
                <td style="font-size: 12px;">${log.entity_type ? escapeHtml(log.entity_type) : '-'}</td>
                <td>${escapeHtml(log.action_description)}</td>
                <td>${statusBadge}</td>
            </tr>
        `;

        // Add reason/notes row if available
        if (log.action_reason || log.error_message) {
            html += `
                <tr style="background: #f8f9fa;">
                    <td colspan="6" style="padding: 8px 12px; font-size: 12px; color: #7f8c8d;">
                        ${log.action_reason ? `<strong>Reason:</strong> ${escapeHtml(log.action_reason)}` : ''}
                        ${log.error_message ? `<strong style="color: #e74c3c;">Error:</strong> ${escapeHtml(log.error_message)}` : ''}
                    </td>
                </tr>
            `;
        }
    });

    html += `
            </tbody>
        </table>
    `;

    container.innerHTML = html;
}

/**
 * Get styled badge for action type
 */
function getActionBadge(actionType) {
    const badges = {
        'script_approved': '<span class="badge badge-success">Script Approved</span>',
        'script_rejected': '<span class="badge badge-danger">Script Rejected</span>',
        'script_deleted': '<span class="badge badge-warning">Script Deleted</span>',
        'scripts_bulk_deleted': '<span class="badge badge-warning">Bulk Deleted</span>',
        'violation_reviewed': '<span class="badge badge-info">Violation Reviewed</span>',
        'violation_deleted': '<span class="badge badge-warning">Violation Deleted</span>',
        'violations_bulk_deleted': '<span class="badge badge-warning">Violations Bulk Deleted</span>',
        'user_created': '<span class="badge badge-success">User Created</span>',
        'user_updated': '<span class="badge badge-info">User Updated</span>',
        'user_deleted': '<span class="badge badge-danger">User Deleted</span>',
        'login_success': '<span class="badge badge-success">Login</span>',
        'login_failed': '<span class="badge badge-danger">Login Failed</span>',
        'logout': '<span class="badge badge-info">Logout</span>'
    };

    return badges[actionType] || `<span class="badge">${escapeHtml(actionType)}</span>`;
}

/**
 * Render pagination controls
 */
function renderAuditPagination(data) {
    const container = document.getElementById('auditPagination');

    if (data.totalPages <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = '<div style="display: flex; justify-content: center; align-items: center; gap: 10px;">';

    // Previous button
    if (data.page > 1) {
        html += `<button onclick="loadAuditTrail(${data.page - 1})" class="secondary">Previous</button>`;
    }

    // Page numbers
    const startPage = Math.max(1, data.page - 2);
    const endPage = Math.min(data.totalPages, data.page + 2);

    if (startPage > 1) {
        html += `<button onclick="loadAuditTrail(1)" class="secondary">1</button>`;
        if (startPage > 2) html += '<span>...</span>';
    }

    for (let i = startPage; i <= endPage; i++) {
        if (i === data.page) {
            html += `<button class="success" disabled>${i}</button>`;
        } else {
            html += `<button onclick="loadAuditTrail(${i})" class="secondary">${i}</button>`;
        }
    }

    if (endPage < data.totalPages) {
        if (endPage < data.totalPages - 1) html += '<span>...</span>';
        html += `<button onclick="loadAuditTrail(${data.totalPages})" class="secondary">${data.totalPages}</button>`;
    }

    // Next button
    if (data.page < data.totalPages) {
        html += `<button onclick="loadAuditTrail(${data.page + 1})" class="secondary">Next</button>`;
    }

    html += `</div>`;
    html += `<p style="text-align: center; color: #7f8c8d; margin-top: 15px; font-size: 14px;">
        Showing ${((data.page - 1) * auditPageSize) + 1} - ${Math.min(data.page * auditPageSize, data.total)} of ${data.total} logs
    </p>`;

    container.innerHTML = html;
}

/**
 * Load audit trail statistics
 */
async function loadAuditStats() {
    try {
        const stats = await apiCall('/api/admin/audit-trail/stats');
        //const stats = await response.json();

        const container = document.getElementById('auditStats');
        container.innerHTML = `
            <div class="stat-card">
                <div class="stat-value">${stats.totalLogs || 0}</div>
                <div class="stat-label">Total Logs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${stats.last24Hours || 0}</div>
                <div class="stat-label">Last 24 Hours</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${stats.last7Days || 0}</div>
                <div class="stat-label">Last 7 Days</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${stats.failedActions || 0}</div>
                <div class="stat-label">Failed Actions</div>
            </div>
        `;
    } catch (error) {
        console.error('Failed to load audit stats:', error);
    }
}

/**
 * Apply audit filters and reload
 */
function applyAuditFilters() {
    loadAuditTrail(1); // Reset to page 1
}

/**
 * Set default date range to last 30 days
 */
function setDefault30DayRange() {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);

    document.getElementById('auditFilterEndDate').value = endDate.toISOString().split('T')[0];
    document.getElementById('auditFilterStartDate').value = startDate.toISOString().split('T')[0];
}