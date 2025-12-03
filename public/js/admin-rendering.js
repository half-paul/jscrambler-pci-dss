/**
 * Rendering Module
 * Renders data tables and UI elements for scripts, violations, and inventory
 */

function renderPendingScripts(scripts) {
    const container = document.getElementById('pendingContent');

    if (scripts.length === 0) {
        container.innerHTML = '<div class="empty-state"><h3>No pending approvals</h3><p>All scripts have been reviewed</p></div>';
        return;
    }

    container.innerHTML = `
        <div class="bulk-actions" id="bulkActions">
            <span class="selection-count" id="selectionCount">0 scripts selected</span>
            <button class="secondary" onclick="selectAll()">Select All</button>
            <button class="secondary" onclick="selectNone()">Select None</button>
            <button class="success" onclick="bulkApprove()" id="bulkApproveBtn">Bulk Approve</button>
            <button class="danger" onclick="bulkReject()" id="bulkRejectBtn">Bulk Reject</button>
        </div>
        <table>
            <thead>
                <tr>
                    <th class="checkbox-cell"><input type="checkbox" id="selectAllCheckbox" onchange="toggleSelectAll(this)"></th>
                    <th>URL</th>
                    <th>Type</th>
                    <th>First Seen</th>
                    <th>Last Loaded From</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${scripts.map(script => `
                    <tr>
                        <td class="checkbox-cell">
                            <input type="checkbox" class="script-checkbox" data-script-id="${script.id}" onchange="updateBulkActions()">
                        </td>
                        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">${script.url}</td>
                        <td><span class="badge">${script.script_type}</span></td>
                        <td>${new Date(script.first_seen).toLocaleString()}</td>
                        <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${script.page_url}</td>
                        <td>
                            <div class="action-buttons">
                                <button class="success" data-script-id="${script.id}" data-script-url="${escapeHtml(script.url)}" data-script-hash="${script.content_hash}" data-script-type="${script.script_type}" data-script-first-seen="${script.first_seen}" onclick="openApprovalModalFromButton(this)">Approve</button>
                                <button class="danger" data-script-id="${script.id}" data-script-url="${escapeHtml(script.url)}" onclick="openRejectionModalFromButton(this)">Reject</button>
                            </div>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

// Bulk selection functions
function updateBulkActions() {
    const checkboxes = document.querySelectorAll('.script-checkbox');
    const checked = Array.from(checkboxes).filter(cb => cb.checked);
    const count = checked.length;

    const bulkActions = document.getElementById('bulkActions');
    const selectionCount = document.getElementById('selectionCount');
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');

    if (count > 0) {
        bulkActions.classList.add('active');
        selectionCount.textContent = `${count} script${count !== 1 ? 's' : ''} selected`;
    } else {
        bulkActions.classList.remove('active');
    }

    // Update select all checkbox state
    if (selectAllCheckbox) {
        selectAllCheckbox.checked = count > 0 && count === checkboxes.length;
        selectAllCheckbox.indeterminate = count > 0 && count < checkboxes.length;
    }
}

function toggleSelectAll(checkbox) {
    const checkboxes = document.querySelectorAll('.script-checkbox');
    checkboxes.forEach(cb => cb.checked = checkbox.checked);
    updateBulkActions();
}

function selectAll() {
    const checkboxes = document.querySelectorAll('.script-checkbox');
    checkboxes.forEach(cb => cb.checked = true);
    updateBulkActions();
}

function selectNone() {
    const checkboxes = document.querySelectorAll('.script-checkbox');
    checkboxes.forEach(cb => cb.checked = false);
    updateBulkActions();
}

function getSelectedScriptIds() {
    const checkboxes = document.querySelectorAll('.script-checkbox:checked');
    return Array.from(checkboxes).map(cb => parseInt(cb.getAttribute('data-script-id')));
}

async function bulkApprove() {
    const scriptIds = getSelectedScriptIds();

    if (scriptIds.length === 0) {
        showNotification('Please select at least one script to approve', 'warning');
        return;
    }

    // Open the bulk approval modal
    openBulkApprovalModal(scriptIds);
}

function openBulkApprovalModal(scriptIds) {
    // Store script IDs for later use
    window.bulkApproveScriptIds = scriptIds;

    // Update the count display
    document.getElementById('bulkApproveCount').textContent =
        `${scriptIds.length} script${scriptIds.length !== 1 ? 's' : ''}`;

    // Set default values
    document.getElementById('bulkBusinessJustification').value = 'Bulk approval of reviewed scripts';
    document.getElementById('bulkScriptPurpose').value = 'Third-party integration';
    document.getElementById('bulkScriptOwner').value = 'Security Team';
    document.getElementById('bulkRiskLevel').value = 'low';
    document.getElementById('bulkApprovalNotes').value = '';

    // Hide any previous errors
    document.getElementById('bulkApprovalError').style.display = 'none';

    // Show the modal
    document.getElementById('bulkApprovalModal').style.display = 'flex';
}

function closeBulkApprovalModal() {
    document.getElementById('bulkApprovalModal').style.display = 'none';
    window.bulkApproveScriptIds = null;
}

async function submitBulkApproval() {
    const scriptIds = window.bulkApproveScriptIds;

    if (!scriptIds || scriptIds.length === 0) {
        closeBulkApprovalModal();
        return;
    }

    // Get form values
    const businessJustification = document.getElementById('bulkBusinessJustification').value.trim();
    const scriptPurpose = document.getElementById('bulkScriptPurpose').value.trim();
    const scriptOwner = document.getElementById('bulkScriptOwner').value.trim() || 'Security Team';
    const riskLevel = document.getElementById('bulkRiskLevel').value || 'low';
    const approvalNotes = document.getElementById('bulkApprovalNotes').value.trim() ||
                          `Bulk approved ${scriptIds.length} scripts`;

    // Validate required fields
    if (!businessJustification) {
        showError('bulkApprovalError', 'Business justification is required');
        return;
    }

    if (!scriptPurpose) {
        showError('bulkApprovalError', 'Script purpose is required');
        return;
    }

    try {
        const response = await apiCall('/api/admin/scripts/bulk-approve', {
            method: 'POST',
            body: JSON.stringify({
                scriptIds,
                businessJustification,
                scriptPurpose,
                scriptOwner,
                riskLevel,
                approvalNotes
            })
        });

        // Close modal
        closeBulkApprovalModal();

        // Show success notification
        showNotification(
            response.message || `Successfully approved ${response.approved} script${response.approved !== 1 ? 's' : ''}`,
            'success'
        );

        if (response.failedIds && response.failedIds.length > 0) {
            console.warn('Failed to approve scripts:', response.failedIds);
            showNotification(
                `${response.failedIds.length} script${response.failedIds.length !== 1 ? 's' : ''} failed to approve`,
                'warning'
            );
        }

        // Refresh the pending scripts list
        await fetchPendingScripts();
        await fetchDashboardStats();

    } catch (error) {
        showError('bulkApprovalError', 'Failed to bulk approve scripts: ' + error.message);
        console.error('Bulk approve error:', error);
    }
}

async function bulkReject() {
    const scriptIds = getSelectedScriptIds();

    if (scriptIds.length === 0) {
        showNotification('Please select at least one script to reject', 'warning');
        return;
    }

    // Open the bulk rejection modal
    openBulkRejectionModal(scriptIds);
}

function openBulkRejectionModal(scriptIds) {
    // Store script IDs for later use
    window.bulkRejectScriptIds = scriptIds;

    // Update the count display
    document.getElementById('bulkRejectCount').textContent =
        `${scriptIds.length} script${scriptIds.length !== 1 ? 's' : ''}`;

    // Set default values
    document.getElementById('bulkRejectionReason').value = 'Unauthorized third-party script';
    document.getElementById('bulkRejectionRiskLevel').value = 'high';
    document.getElementById('bulkRejectionNotes').value = '';

    // Hide any previous errors
    document.getElementById('bulkRejectionError').style.display = 'none';

    // Show the modal
    document.getElementById('bulkRejectionModal').style.display = 'flex';
}

function closeBulkRejectionModal() {
    document.getElementById('bulkRejectionModal').style.display = 'none';
    window.bulkRejectScriptIds = null;
}

async function submitBulkRejection() {
    const scriptIds = window.bulkRejectScriptIds;

    if (!scriptIds || scriptIds.length === 0) {
        closeBulkRejectionModal();
        return;
    }

    // Get form values
    const rejectionReason = document.getElementById('bulkRejectionReason').value.trim();
    const riskLevel = document.getElementById('bulkRejectionRiskLevel').value || 'high';
    const notes = document.getElementById('bulkRejectionNotes').value.trim() ||
                 `Bulk rejected ${scriptIds.length} scripts`;

    // Validate required fields
    if (!rejectionReason) {
        showError('bulkRejectionError', 'Rejection reason is required');
        return;
    }

    try {
        const response = await apiCall('/api/admin/scripts/bulk-reject', {
            method: 'POST',
            body: JSON.stringify({
                scriptIds,
                rejectionReason,
                riskLevel,
                notes
            })
        });

        // Close modal
        closeBulkRejectionModal();

        // Show success notification
        showNotification(
            response.message || `Successfully rejected ${response.rejected} script${response.rejected !== 1 ? 's' : ''}`,
            'success'
        );

        if (response.failedIds && response.failedIds.length > 0) {
            console.warn('Failed to reject scripts:', response.failedIds);
            showNotification(
                `${response.failedIds.length} script${response.failedIds.length !== 1 ? 's' : ''} failed to reject`,
                'warning'
            );
        }

        // Refresh the pending scripts list
        await fetchPendingScripts();
        await fetchDashboardStats();

    } catch (error) {
        showError('bulkRejectionError', 'Failed to bulk reject scripts: ' + error.message);
        console.error('Bulk reject error:', error);
    }
}

// ============================================================================
// DELETE SCRIPT FUNCTIONS
// ============================================================================

// currentDeleteScriptId is declared in admin-config.js

function deleteInventoryScript(scriptId, scriptUrl) {
    currentDeleteScriptId = scriptId;
    document.getElementById('deleteScriptId').textContent = scriptId;
    document.getElementById('deleteScriptUrl').textContent = scriptUrl;
    document.getElementById('deleteScriptError').style.display = 'none';
    document.getElementById('deleteScriptModal').style.display = 'flex';
}

function closeDeleteScriptModal() {
    document.getElementById('deleteScriptModal').style.display = 'none';
    currentDeleteScriptId = null;
}

async function confirmDeleteScript() {
    if (!currentDeleteScriptId) {
        closeDeleteScriptModal();
        return;
    }

    try {
        const response = await apiCall(`/api/admin/scripts/${currentDeleteScriptId}`, {
            method: 'DELETE'
        });

        closeDeleteScriptModal();

        showNotification(
            response.message || 'Script deleted successfully',
            'success'
        );

        // Refresh the inventory
        await searchInventory();
        await fetchDashboardStats();

    } catch (error) {
        showError('deleteScriptError', 'Failed to delete script: ' + error.message);
        console.error('Delete script error:', error);
    }
}

// ============================================================================
// BULK DELETE FUNCTIONS
// ============================================================================

function getSelectedInventoryScriptIds() {
    const checkboxes = document.querySelectorAll('.inventory-checkbox:checked');
    return Array.from(checkboxes).map(cb => parseInt(cb.getAttribute('data-script-id')));
}

function toggleAllInventoryCheckboxes(checkbox) {
    const checkboxes = document.querySelectorAll('.inventory-checkbox');
    checkboxes.forEach(cb => cb.checked = checkbox.checked);
    updateInventoryBulkActions();
}

function updateInventoryBulkActions() {
    const selectedIds = getSelectedInventoryScriptIds();
    const bulkActions = document.getElementById('inventoryBulkActions');
    const selectedCount = document.getElementById('inventorySelectedCount');

    if (selectedIds.length > 0) {
        bulkActions.style.display = 'flex';
        selectedCount.textContent = `${selectedIds.length} script${selectedIds.length !== 1 ? 's' : ''} selected`;
    } else {
        bulkActions.style.display = 'none';
    }

    // Update "select all" checkbox state
    const allCheckboxes = document.querySelectorAll('.inventory-checkbox');
    const selectAllCheckbox = document.getElementById('inventorySelectAll');
    if (selectAllCheckbox && allCheckboxes.length > 0) {
        selectAllCheckbox.checked = selectedIds.length === allCheckboxes.length;
    }
}

function clearInventorySelection() {
    const checkboxes = document.querySelectorAll('.inventory-checkbox');
    checkboxes.forEach(cb => cb.checked = false);
    const selectAllCheckbox = document.getElementById('inventorySelectAll');
    if (selectAllCheckbox) selectAllCheckbox.checked = false;
    updateInventoryBulkActions();
}

function bulkDeleteInventory() {
    const scriptIds = getSelectedInventoryScriptIds();

    if (scriptIds.length === 0) {
        showNotification('Please select at least one script to delete', 'warning');
        return;
    }

    // Open the bulk delete modal
    openBulkDeleteModal(scriptIds);
}

function openBulkDeleteModal(scriptIds) {
    window.bulkDeleteScriptIds = scriptIds;

    document.getElementById('bulkDeleteCount').textContent =
        `${scriptIds.length} script${scriptIds.length !== 1 ? 's' : ''}`;

    document.getElementById('bulkDeletionReason').value = '';
    document.getElementById('bulkDeleteError').style.display = 'none';
    document.getElementById('bulkDeleteModal').style.display = 'flex';
}

function closeBulkDeleteModal() {
    document.getElementById('bulkDeleteModal').style.display = 'none';
    window.bulkDeleteScriptIds = null;
}

async function submitBulkDelete() {
    const scriptIds = window.bulkDeleteScriptIds;

    if (!scriptIds || scriptIds.length === 0) {
        closeBulkDeleteModal();
        return;
    }

    const deletionReason = document.getElementById('bulkDeletionReason').value.trim();

    if (!deletionReason) {
        showError('bulkDeleteError', 'Deletion reason is required');
        return;
    }

    try {
        const response = await apiCall('/api/admin/scripts/bulk-delete', {
            method: 'POST',
            body: JSON.stringify({
                scriptIds,
                deletionReason
            })
        });

        closeBulkDeleteModal();

        showNotification(
            response.message || `Successfully deleted ${response.deleted} script${response.deleted !== 1 ? 's' : ''}`,
            'success'
        );

        if (response.failedIds && response.failedIds.length > 0) {
            console.warn('Failed to delete scripts:', response.failedIds);
            showNotification(
                `${response.failedIds.length} script${response.failedIds.length !== 1 ? 's' : ''} failed to delete`,
                'warning'
            );
        }

        // Clear selection and refresh
        clearInventorySelection();
        await searchInventory();
        await fetchDashboardStats();

    } catch (error) {
        showError('bulkDeleteError', 'Failed to bulk delete scripts: ' + error.message);
        console.error('Bulk delete error:', error);
    }
}

function renderViolations(violations) {
    const container = document.getElementById('violationsContent');

    if (violations.length === 0) {
        container.innerHTML = '<div class="empty-state"><h3>No violations</h3><p>System is operating normally</p></div>';
        return;
    }

    // Group violations by script_url and count (already done on server, but ensure consistency)
    const severityColors = {
        'LOW': 'low',
        'MEDIUM': 'medium',
        'HIGH': 'high',
        'CRITICAL': 'critical'
    };

    container.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>Script</th>
                    <th>Violation Count</th>
                    <th>Last Type</th>
                    <th>Severity</th>
                    <th>Last Detected</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                ${violations.map(v => `
                    <tr>
                        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(v.script_url)}">${escapeHtml(v.script_url)}</td>
                        <td><strong>${v.violation_count || 1}</strong></td>
                        <td>${v.last_violation_type || '-'}</td>
                        <td><span class="badge ${severityColors[v.highest_severity] || 'high'}">${v.highest_severity || 'HIGH'}</span></td>
                        <td>${v.last_detected_at ? new Date(v.last_detected_at).toLocaleString() : '-'}</td>
                        <td><span class="badge ${v.review_status || 'pending'}">${v.review_status || 'pending'}</span></td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
        <div style="margin-top: 20px; color: #666; font-size: 14px;">
            Showing ${violations.length} script${violations.length !== 1 ? 's' : ''} with violations
        </div>
    `;
}

function renderInventory(scripts) {
    const container = document.getElementById('inventoryContent');

    if (scripts.length === 0) {
        container.innerHTML = '<div class="empty-state"><h3>No scripts</h3><p>No scripts have been discovered yet</p></div>';
        return;
    }

    const statusColors = {
        'approved': 'approved',
        'pending_approval': 'pending',
        'rejected': 'rejected',
        'flagged': 'pending'
    };

    const statusLabels = {
        'approved': 'Approved',
        'pending_approval': 'Pending',
        'rejected': 'Rejected',
        'flagged': 'Flagged'
    };

    container.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th><input type="checkbox" id="inventorySelectAll" onchange="toggleAllInventoryCheckboxes(this)"></th>
                    <th>ID</th>
                    <th>URL</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Access Count</th>
                    <th>Last Registered IP</th>
                    <th>Variation</th>
                    <th>First Seen</th>
                    <th>Approved By</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${scripts.map(script => {
                    // Only show IP for non-approved scripts
                    const showIp = script.status !== 'approved' && script.status !== 'auto_approved' && script.last_registered_ip;
                    const ipDisplay = showIp ?
                        `<span style="font-family: monospace; font-size: 11px;" title="Last registered: ${script.last_registered_at ? new Date(script.last_registered_at).toLocaleString() : 'N/A'}">${script.last_registered_ip}</span>` :
                        '<span style="color: #95a5a6;">-</span>';

                    return `
                    <tr>
                        <td onclick="event.stopPropagation()">
                            <input type="checkbox" class="inventory-checkbox" data-script-id="${script.id}" onchange="updateInventoryBulkActions()">
                        </td>
                        <td onclick="showScriptDetails(${script.id})" style="cursor: pointer;" title="Click to view details">${script.id}</td>
                        <td onclick="showScriptDetails(${script.id})" style="cursor: pointer; max-width: 300px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(script.url)}">${escapeHtml(script.url)}</td>
                        <td onclick="showScriptDetails(${script.id})" style="cursor: pointer;"><span class="badge">${script.script_type}</span></td>
                        <td onclick="showScriptDetails(${script.id})" style="cursor: pointer;"><span class="badge ${statusColors[script.status] || ''}">${statusLabels[script.status] || script.status}</span></td>
                        <td onclick="showScriptDetails(${script.id})" style="cursor: pointer;"><strong>${script.access_count || 0}</strong></td>
                        <td onclick="showScriptDetails(${script.id})" style="cursor: pointer;">${ipDisplay}</td>
                        <td onclick="showScriptDetails(${script.id})" style="cursor: pointer;">${script.is_variation ? `<span class="badge warning" title="Variation #${script.variation_number} of script #${script.parent_script_id}">Var #${script.variation_number}</span>` : '-'}</td>
                        <td onclick="showScriptDetails(${script.id})" style="cursor: pointer;">${new Date(script.first_seen).toLocaleString()}</td>
                        <td onclick="showScriptDetails(${script.id})" style="cursor: pointer;">${script.approved_by || '-'}</td>
                        <td onclick="event.stopPropagation()">
                            <button class="danger small" onclick="deleteInventoryScript(${script.id}, '${escapeHtml(script.url).replace(/'/g, "\\'")}')">Delete</button>
                        </td>
                    </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
        <div style="margin-top: 20px; color: #666; font-size: 14px;">
            Showing ${scripts.length} script${scripts.length !== 1 ? 's' : ''} (Click any row to view details)
        </div>
    `;
}

// Modals
function openApprovalModal(id, url, hash, type, firstSeen) {
    currentScript = id;
    document.getElementById('modalUrl').textContent = url;
    document.getElementById('modalHash').textContent = hash;
    document.getElementById('modalType').textContent = type;
    document.getElementById('modalFirstSeen').textContent = new Date(firstSeen).toLocaleString();

    // Clear form
    document.getElementById('businessJustification').value = '';
    document.getElementById('scriptPurpose').value = '';
    document.getElementById('scriptOwner').value = '';
    document.getElementById('approvalNotes').value = '';
    document.getElementById('approvalError').style.display = 'none';
    
    // Set default risk level to "low"
    document.getElementById('riskLevel').value = 'low';

    document.getElementById('approvalModal').classList.add('active');
}