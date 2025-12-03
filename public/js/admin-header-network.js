/**
 * Header and Network Monitoring Module
 * PCI DSS 11.6.1 compliance - monitors HTTP headers and network requests
 */

// =====================================================================
// HTTP Header Monitoring Functions (PCI DSS 11.6.1)
// =====================================================================

function showHeaderSubTab(tabId, clickedElement) {
    document.querySelectorAll('#headers .tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.header-subtab').forEach(s => s.style.display = 'none');
    clickedElement.classList.add('active');
    document.getElementById(tabId).style.display = 'block';

    if (tabId === 'headerViolations') fetchHeaderViolations();
    else if (tabId === 'headerBaselines') fetchHeaderBaselines();
}

async function fetchHeaderViolations() {
    const container = document.getElementById('headerViolationsContent');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const response = await apiCall('/api/admin/headers/violations');
        if (response.success) {
            renderHeaderViolations(response.data);
        }
    } catch (error) {
        container.innerHTML = `<div class="error-message">Error: ${error.message}</div>`;
    }
}

function renderHeaderViolations(violations) {
    const container = document.getElementById('headerViolationsContent');

    if (!violations || violations.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <h3>No Header Violations</h3>
                <p>No HTTP header tampering detected.</p>
            </div>`;
        return;
    }

    container.innerHTML = `
        <div style="margin-bottom: 15px; padding: 10px; background: #f8f9fa; border-radius: 4px;">
            <strong>Note:</strong> Duplicate violations (same page, header, and type) are automatically grouped into a single record.
            The "Last Detected" timestamp shows when the violation was most recently seen.
            <br><br>
            <strong>Smart Reopening:</strong> If you mark a violation as "resolved" or "false positive" but it occurs again,
            the system will automatically reopen it and change the status back to "pending" with an alert.
        </div>
        <div style="margin-bottom: 15px; display: flex; gap: 10px; align-items: center;">
            <button class="success" onclick="bulkResolveHeaderViolations()" id="bulkResolveHeaderBtn" disabled>
                Bulk Resolve (<span id="headerViolationsSelectedCount">0</span>)
            </button>
            <button class="secondary" onclick="bulkFalsePositiveHeaderViolations()" id="bulkFalsePositiveHeaderBtn" disabled>
                Bulk Mark False Positive (<span id="headerViolationsSelectedCount2">0</span>)
            </button>
            <label style="margin-left: auto; cursor: pointer;">
                <input type="checkbox" id="selectAllHeaderViolations" onchange="toggleAllHeaderViolations(this.checked)">
                Select All
            </label>
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 40px;">
                        <input type="checkbox" id="selectAllHeaderViolationsHeader" onchange="toggleAllHeaderViolations(this.checked)">
                    </th>
                    <th>Page URL</th>
                    <th>Header</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Last Detected</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${violations.map(v => `
                    <tr>
                        <td>
                            <input type="checkbox" class="header-violation-checkbox" value="${v.id}" onchange="updateHeaderViolationBulkButtons()">
                        </td>
                        <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(v.page_url || '')}</td>
                        <td><strong>${escapeHtml(v.header_name || '')}</strong></td>
                        <td><span class="badge">${v.violation_type}</span></td>
                        <td><span class="badge ${v.severity?.toLowerCase() || 'high'}">${v.severity}</span></td>
                        <td>${new Date(v.detected_at).toLocaleString()}</td>
                        <td><span class="badge ${v.review_status}">${v.review_status}</span></td>
                        <td class="action-buttons">
                            <button class="small success" onclick="reviewHeaderViolation(${v.id}, 'resolved')">Resolve</button>
                            <button class="small secondary" onclick="reviewHeaderViolation(${v.id}, 'false_positive')">False Positive</button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>`;
}

async function reviewHeaderViolation(id, status) {
    const notes = prompt('Enter review notes (optional):');
    try {
        await apiCall(`/api/admin/headers/violations/${id}/review`, {
            method: 'POST',
            body: JSON.stringify({ status, notes })
        });
        alert('Violation reviewed successfully');
        fetchHeaderViolations();
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Bulk operations for header violations
function toggleAllHeaderViolations(checked) {
    document.querySelectorAll('.header-violation-checkbox').forEach(cb => {
        cb.checked = checked;
    });
    document.getElementById('selectAllHeaderViolations').checked = checked;
    document.getElementById('selectAllHeaderViolationsHeader').checked = checked;
    updateHeaderViolationBulkButtons();
}

function updateHeaderViolationBulkButtons() {
    const checkboxes = document.querySelectorAll('.header-violation-checkbox:checked');
    const count = checkboxes.length;

    document.getElementById('headerViolationsSelectedCount').textContent = count;
    document.getElementById('headerViolationsSelectedCount2').textContent = count;
    document.getElementById('bulkResolveHeaderBtn').disabled = count === 0;
    document.getElementById('bulkFalsePositiveHeaderBtn').disabled = count === 0;

    // Update select all checkbox state
    const allCheckboxes = document.querySelectorAll('.header-violation-checkbox');
    const allChecked = allCheckboxes.length > 0 && checkboxes.length === allCheckboxes.length;
    document.getElementById('selectAllHeaderViolations').checked = allChecked;
    document.getElementById('selectAllHeaderViolationsHeader').checked = allChecked;
}

async function bulkResolveHeaderViolations() {
    const checkboxes = document.querySelectorAll('.header-violation-checkbox:checked');
    const ids = Array.from(checkboxes).map(cb => parseInt(cb.value));

    if (ids.length === 0) {
        alert('Please select at least one violation');
        return;
    }

    const notes = prompt(`Enter review notes for ${ids.length} violation(s) (optional):`);
    if (notes === null) return; // User cancelled

    try {
        const response = await apiCall('/api/admin/headers/violations/bulk-resolve', {
            method: 'POST',
            body: JSON.stringify({ ids, review_notes: notes || `Bulk resolved ${ids.length} violations` })
        });

        alert(`Successfully resolved ${response.resolved || ids.length} violation(s)`);
        fetchHeaderViolations();
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function bulkFalsePositiveHeaderViolations() {
    const checkboxes = document.querySelectorAll('.header-violation-checkbox:checked');
    const ids = Array.from(checkboxes).map(cb => parseInt(cb.value));

    if (ids.length === 0) {
        alert('Please select at least one violation');
        return;
    }

    const notes = prompt(`Enter review notes for ${ids.length} violation(s) (optional):`);
    if (notes === null) return; // User cancelled

    try {
        const response = await apiCall('/api/admin/headers/violations/bulk-false-positive', {
            method: 'POST',
            body: JSON.stringify({ ids, review_notes: notes || `Bulk marked ${ids.length} violations as false positive` })
        });

        alert(`Successfully marked ${response.marked || ids.length} violation(s) as false positive`);
        fetchHeaderViolations();
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function fetchHeaderBaselines() {
    const container = document.getElementById('headerBaselinesContent');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const response = await apiCall('/api/admin/headers/baselines');
        if (response.success) {
            renderHeaderBaselines(response.data);
        }
    } catch (error) {
        container.innerHTML = `<div class="error-message">Error: ${error.message}</div>`;
    }
}

function renderHeaderBaselines(baselines) {
    const container = document.getElementById('headerBaselinesContent');

    if (!baselines || baselines.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <h3>No Header Baselines</h3>
                <p>No pages are being monitored for header changes yet.</p>
                <p style="margin-top: 15px; font-size: 13px; color: #95a5a6;">
                    Header baselines are automatically created when a page with the HTTP Header Monitor loads.<br>
                    Include <code>http-header-monitor.js</code> on your payment pages to start monitoring.
                </p>
            </div>`;
        return;
    }

    container.innerHTML = `
        <div style="margin-bottom: 15px;">
            <span style="color: #7f8c8d;">Monitoring ${baselines.length} page(s) for header changes</span>
        </div>
        ${baselines.map(b => `
            <div style="background: #fff; border: 1px solid #ecf0f1; border-radius: 8px; margin-bottom: 20px; overflow: hidden;">
                <div style="background: #f8f9fa; padding: 15px; border-bottom: 1px solid #ecf0f1;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong style="font-size: 14px;">Page URL:</strong>
                            <a href="${escapeHtml(b.page_url || '')}" target="_blank" style="color: #3498db; margin-left: 10px; word-break: break-all;">
                                ${escapeHtml(b.page_url || '')}
                            </a>
                        </div>
                        <div style="text-align: right; color: #7f8c8d; font-size: 12px;">
                            <div>Created: ${new Date(b.created_at).toLocaleString()}</div>
                            <div>Last Verified: ${b.last_verified ? new Date(b.last_verified).toLocaleString() : '-'}</div>
                        </div>
                    </div>
                </div>
                <div style="padding: 15px;">
                    <h4 style="margin-bottom: 10px; color: #2c3e50;">Monitored Headers (${Object.keys(b.headers || {}).length})</h4>
                    <table style="font-size: 13px;">
                        <thead>
                            <tr>
                                <th style="width: 250px;">Header Name</th>
                                <th>Baseline Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${Object.entries(b.headers || {}).map(([name, value]) => `
                                <tr>
                                    <td><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 3px;">${escapeHtml(name)}</code></td>
                                    <td style="word-break: break-all; font-family: monospace; font-size: 12px; color: #555;">${escapeHtml(value || '(empty)')}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `).join('')}`;
}

// =====================================================================
// Network Monitoring Functions (PCI DSS 11.6.1)
// =====================================================================

function showNetworkSubTab(tabId, clickedElement) {
    document.querySelectorAll('#network .tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.network-subtab').forEach(s => s.style.display = 'none');
    clickedElement.classList.add('active');
    document.getElementById(tabId).style.display = 'block';

    if (tabId === 'networkViolations') fetchNetworkViolations();
    else if (tabId === 'networkWhitelist') fetchNetworkWhitelist();
}

async function fetchNetworkViolations() {
    const container = document.getElementById('networkViolationsContent');
    container.innerHTML = '<div class="loading">Loading...</div>';

    const blockedOnly = document.getElementById('showBlockedOnly')?.checked;
    const params = blockedOnly ? '?blocked=true' : '';

    try {
        const response = await apiCall(`/api/admin/network/violations${params}`);
        if (response.success) {
            renderNetworkViolations(response.data);
        }
    } catch (error) {
        container.innerHTML = `<div class="error-message">Error: ${error.message}</div>`;
    }
}

function renderNetworkViolations(violations) {
    const container = document.getElementById('networkViolationsContent');

    if (!violations || violations.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <h3>No Network Violations</h3>
                <p>No unauthorized network requests detected.</p>
            </div>`;
        return;
    }

    container.innerHTML = `
        <div style="margin-bottom: 15px; padding: 10px; background: #f8f9fa; border-radius: 4px;">
            <strong>Note:</strong> Duplicate violations (same page, destination, and request type) are automatically grouped into a single record.
            The "Last Detected" timestamp shows when the violation was most recently seen.
            <br><br>
            <strong>Smart Reopening:</strong> If you mark a violation as "resolved", "false positive", or "whitelisted" but it occurs again,
            the system will automatically reopen it and change the status back to "pending" with a high-priority alert.
        </div>
        <table>
            <thead>
                <tr>
                    <th>Source Page</th>
                    <th>Destination</th>
                    <th>Type</th>
                    <th>Blocked</th>
                    <th>Last Detected</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${violations.map(v => `
                    <tr>
                        <td style="max-width: 150px; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(v.page_url || '')}</td>
                        <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">
                            <strong>${escapeHtml(v.destination_origin || '')}</strong><br>
                            <small style="color: #7f8c8d;">${escapeHtml(v.destination_url || '')}</small>
                        </td>
                        <td><span class="badge">${v.request_type}</span></td>
                        <td>${v.blocked ? '<span class="badge high">BLOCKED</span>' : '<span class="badge low">Reported</span>'}</td>
                        <td>${new Date(v.detected_at).toLocaleString()}</td>
                        <td><span class="badge ${v.review_status}">${v.review_status}</span></td>
                        <td class="action-buttons">
                            <button class="small success" onclick="whitelistFromViolation(${v.id})">Whitelist</button>
                            <button class="small secondary" onclick="reviewNetworkViolation(${v.id}, 'resolved')">Resolve</button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>`;
}

async function reviewNetworkViolation(id, status) {
    const notes = prompt('Enter review notes (optional):');
    try {
        await apiCall(`/api/admin/network/violations/${id}/review`, {
            method: 'POST',
            body: JSON.stringify({ status, notes })
        });
        alert('Violation reviewed successfully');
        fetchNetworkViolations();
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function whitelistFromViolation(id) {
    const justification = prompt('Enter business justification for whitelisting this domain:');
    if (!justification) return;

    try {
        await apiCall(`/api/admin/network/violations/${id}/whitelist`, {
            method: 'POST',
            body: JSON.stringify({ businessJustification: justification })
        });
        alert('Domain whitelisted successfully');
        fetchNetworkViolations();
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function fetchNetworkWhitelist() {
    const container = document.getElementById('networkWhitelistContent');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const response = await apiCall('/api/admin/network/whitelist');
        if (response.success) {
            renderNetworkWhitelist(response.data);
        }
    } catch (error) {
        container.innerHTML = `<div class="error-message">Error: ${error.message}</div>`;
    }
}

function renderNetworkWhitelist(whitelist) {
    const container = document.getElementById('networkWhitelistContent');

    if (!whitelist || whitelist.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <h3>No Whitelisted Domains</h3>
                <p>Add trusted domains that are allowed to receive network requests.</p>
            </div>`;
        return;
    }

    container.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Pattern Type</th>
                    <th>Justification</th>
                    <th>Added By</th>
                    <th>Added At</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${whitelist.map(w => `
                    <tr>
                        <td><strong>${escapeHtml(w.domain || '')}</strong></td>
                        <td>${w.pattern_type || 'exact'}</td>
                        <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(w.business_justification || '-')}</td>
                        <td>${escapeHtml(w.added_by || '-')}</td>
                        <td>${new Date(w.added_at).toLocaleString()}</td>
                        <td class="action-buttons">
                            <button class="small danger" onclick="removeFromWhitelist(${w.id})">Remove</button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>`;
}

async function removeFromWhitelist(id) {
    if (!confirm('Are you sure you want to remove this domain from the whitelist?')) return;

    try {
        await apiCall(`/api/admin/network/whitelist/${id}`, { method: 'DELETE' });
        alert('Domain removed from whitelist');
        fetchNetworkWhitelist();
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

function openAddWhitelistModal() {
    const domain = prompt('Enter domain to whitelist (e.g., https://api.example.com):');
    if (!domain) return;

    const justification = prompt('Enter business justification:');
    if (!justification) return;

    // For simplicity, directly add to whitelist - in production use a proper modal
    addToWhitelist(domain, justification);
}

async function addToWhitelist(domain, justification) {
    // This would require a new endpoint - for now show message
    alert('To add a new domain to whitelist, please use the "Whitelist" action on a network violation, or add via database.');
}

// MFA Status and Management
