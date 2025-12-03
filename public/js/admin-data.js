/**
 * Data Loading and Rendering Module
 * Fetches and renders data for various admin panel sections
 */

// Data Loading
async function fetchDashboard() {
    const data = await apiCall('/api/admin/dashboard');

    document.getElementById('totalScripts').textContent = data.compliance?.total_scripts || 0;
    document.getElementById('pendingScripts').textContent = data.compliance?.pending_scripts || 0;
    document.getElementById('approvedScripts').textContent = data.compliance?.approved_scripts || 0;
    document.getElementById('totalViolations').textContent = data.violations?.total_violations || 0;
}

async function fetchPendingScripts() {
    const data = await apiCall('/api/admin/scripts/pending');
    renderPendingScripts(data.data || []);
}

async function fetchViolations() {
    const data = await apiCall('/api/admin/violations');
    renderViolations(data.data || []);
}

function searchInventory() {
    fetchInventory();
}

async function fetchInventory() {
    const query = document.getElementById('searchQuery')?.value || '';
    const status = document.getElementById('statusFilter')?.value || '';
    const type = document.getElementById('typeFilter')?.value || '';

    const params = new URLSearchParams();
    if (query) params.append('q', query);
    if (status) params.append('status', status);
    if (type) params.append('type', type);
    params.append('limit', '100');

    const data = await apiCall(`/api/admin/scripts/search?${params.toString()}`);
    renderInventory(data.data || []);
}

function loadData() {
    fetchDashboard();
    fetchPendingScripts();
    fetchViolations();
    fetchInventory();
    loadUsers();
    updateMfaStatus();
    updateAccountInfo();
    fetchHeaderViolations();
    fetchNetworkViolations();
}
