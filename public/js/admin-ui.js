/**
 * UI Module
 * Handles UI interactions, tab switching, and display updates
 */

// Tab Management
function showTab(tabName, clickedElement) {
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.content-section').forEach(section => section.classList.remove('active'));

    // If called from onclick, use the clicked element; otherwise find the tab button
    if (clickedElement) {
        clickedElement.classList.add('active');
    } else {
        // Find the tab button by matching the onclick attribute
        const tabButtons = document.querySelectorAll('.tab');
        tabButtons.forEach(btn => {
            if (btn.getAttribute('onclick')?.includes(`'${tabName}'`)) {
                btn.classList.add('active');
            }
        });
    }

    // Show the selected content section
    const section = document.getElementById(tabName);
    if (section) {
        section.classList.add('active');

        // Load data for specific tabs when they become active
        if (tabName === 'audit') {
            setDefault30DayRange();
            loadAuditTrail();
            loadAuditStats();
        } else if (tabName === 'security') {
            updateMfaStatus();
            updateAccountInfo();
        } else if (tabName === 'users') {
            loadUsers();
        } else if (tabName === 'headers') {
            fetchHeaderViolations();
        } else if (tabName === 'network') {
            fetchNetworkViolations();
        }
    }
}

// Header Monitoring Sub-tabs
function showHeaderSubTab(tabId, clickedElement) {
    // Remove active class from all header subtabs
    document.querySelectorAll('#headers .tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.header-subtab').forEach(tab => tab.style.display = 'none');

    // Add active class to clicked tab
    if (clickedElement) {
        clickedElement.classList.add('active');
    }

    // Show selected subtab
    const subtab = document.getElementById(tabId);
    if (subtab) {
        subtab.style.display = 'block';
    }

    // Load data for the selected subtab
    if (tabId === 'headerViolations') {
        fetchHeaderViolations();
    } else if (tabId === 'headerBaselines') {
        fetchHeaderBaselines();
    }
}

// Network Monitoring Sub-tabs
function showNetworkSubTab(tabId, clickedElement) {
    // Remove active class from all network subtabs
    document.querySelectorAll('#network .tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.network-subtab').forEach(tab => tab.style.display = 'none');

    // Add active class to clicked tab
    if (clickedElement) {
        clickedElement.classList.add('active');
    }

    // Show selected subtab
    const subtab = document.getElementById(tabId);
    if (subtab) {
        subtab.style.display = 'block';
    }

    // Load data for the selected subtab
    if (tabId === 'networkViolations') {
        fetchNetworkViolations();
    } else if (tabId === 'networkWhitelist') {
        fetchNetworkWhitelist();
    }
}

// Update account information display
function updateAccountInfo() {
    const user = AdminConfig.getCurrentUser();
    if (!user) {
        const stored = localStorage.getItem('current_user');
        if (stored) {
            AdminConfig.setCurrentUser(JSON.parse(stored));
            updateAccountInfo(); // Retry
        }
        return;
    }

    document.getElementById('accountUsername').textContent = user.username || '-';
    document.getElementById('accountEmail').textContent = user.email || '-';
    document.getElementById('accountRole').textContent = user.role || '-';
}
