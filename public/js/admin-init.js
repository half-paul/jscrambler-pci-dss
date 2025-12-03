/**
 * Initialization Module
 * Handles page initialization and event listeners
 */

// Add click outside to close modals
window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        const modals = ['approvalModal', 'rejectionModal', 'scriptDetailsModal', 'userModal', 'mfaSetupModal',
                        'bulkApprovalModal', 'bulkRejectionModal', 'deleteScriptModal', 'bulkDeleteModal'];
        modals.forEach(modalId => {
            if (event.target.id === modalId) {
                document.getElementById(modalId).classList.remove('active');
            }
        });
    }
};

// Handle Enter key on login form
document.addEventListener('DOMContentLoaded', function() {
    // Enter key on username field
    const usernameInput = document.getElementById('username');
    if (usernameInput) {
        usernameInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                document.getElementById('password').focus();
            }
        });
    }

    // Enter key on password field
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                login();
            }
        });
    }

    // Enter key on MFA code field
    const mfaCodeInput = document.getElementById('mfaCode');
    if (mfaCodeInput) {
        mfaCodeInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                verifyMFA();
            }
        });
    }

    // Set login button click handler
    const loginButton = document.getElementById('loginButton');
    if (loginButton) {
        loginButton.addEventListener('click', function(e) {
            e.preventDefault();
            login();
        });
    }

    // Check if already logged in
    const token = localStorage.getItem('jwt_token');
    const storedUser = localStorage.getItem('current_user');
    if (token && storedUser) {
        AdminConfig.setAuthToken(token);
        AdminConfig.setRefreshToken(localStorage.getItem('refresh_token'));
        AdminConfig.setCurrentUser(JSON.parse(storedUser));

        // Show dashboard
        document.getElementById('authSection').style.display = 'none';
        document.getElementById('mainDashboard').style.display = 'block';

        // Load data
        loadData();
    }
});
