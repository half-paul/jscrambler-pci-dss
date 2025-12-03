/**
 * Utility Functions Module
 * Helper functions for common operations
 */

// Show error message
function showError(elementId, message) {
    const el = document.getElementById(elementId);
    el.textContent = message;
    el.style.display = 'block';
}

// Show notification toast
function showNotification(message, type = 'info') {
    const container = document.getElementById('notificationContainer');
    const notification = document.createElement('div');

    // Set styles based on type
    const styles = {
        success: { bg: '#d4edda', border: '#28a745', color: '#155724' },
        error: { bg: '#f8d7da', border: '#dc3545', color: '#721c24' },
        warning: { bg: '#fff3cd', border: '#ffc107', color: '#856404' },
        info: { bg: '#d1ecf1', border: '#17a2b8', color: '#0c5460' }
    };

    const style = styles[type] || styles.info;

    notification.style.cssText = `
        background: ${style.bg};
        border-left: 4px solid ${style.border};
        color: ${style.color};
        padding: 15px 20px;
        margin-bottom: 10px;
        border-radius: 4px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        animation: slideIn 0.3s ease-out;
        position: relative;
        display: flex;
        justify-content: space-between;
        align-items: center;
    `;

    notification.innerHTML = `
        <span>${escapeHtml(message)}</span>
        <button onclick="this.parentElement.remove()" style="
            background: none;
            border: none;
            color: ${style.color};
            cursor: pointer;
            font-size: 20px;
            padding: 0 5px;
            margin-left: 15px;
        ">&times;</button>
    `;

    container.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => notification.remove(), 300);
        }
    }, 5000);
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text ? String(text).replace(/[&<>"']/g, m => map[m]) : '';
}

// Show user error message
function showUserError(message) {
    const errorDiv = document.getElementById('userError');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
}

// Get action badge for audit trail
function getActionBadge(actionType) {
    const actionLabels = {
        'script_approved': { label: 'Script Approved', class: 'success' },
        'script_rejected': { label: 'Script Rejected', class: 'danger' },
        'script_deleted': { label: 'Script Deleted', class: 'danger' },
        'scripts_bulk_deleted': { label: 'Bulk Delete', class: 'danger' },
        'violation_reviewed': { label: 'Violation Reviewed', class: 'info' },
        'violations_bulk_deleted': { label: 'Bulk Delete Violations', class: 'danger' },
        'header_violation_reviewed': { label: 'Header Reviewed', class: 'info' },
        'header_violations_bulk_deleted': { label: 'Bulk Delete Headers', class: 'danger' },
        'header_baselines_bulk_deleted': { label: 'Bulk Delete Baselines', class: 'danger' },
        'network_violation_reviewed': { label: 'Network Reviewed', class: 'info' },
        'network_violations_bulk_deleted': { label: 'Bulk Delete Network', class: 'danger' },
        'user_created': { label: 'User Created', class: 'success' },
        'user_updated': { label: 'User Updated', class: 'info' },
        'user_deleted': { label: 'User Deleted', class: 'danger' },
        'login_success': { label: 'Login', class: 'success' },
        'login_failed': { label: 'Login Failed', class: 'danger' }
    };

    const action = actionLabels[actionType] || { label: actionType, class: '' };
    return `<span class="badge ${action.class}">${action.label}</span>`;
}

// Set default 30-day date range for filters
function setDefault30DayRange() {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);

    const formatDate = (date) => {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    };

    document.getElementById('auditFilterStartDate').value = formatDate(startDate);
    document.getElementById('auditFilterEndDate').value = formatDate(endDate);
}
