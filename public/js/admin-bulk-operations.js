/**
 * Bulk Operations Module
 * Handles bulk selection, approval, rejection, and deletion of scripts
 */

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

