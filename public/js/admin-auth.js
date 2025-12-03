/**
 * Authentication Module
 * Handles user login, MFA, logout, and token management
 */

// Authentication - Login with username/password
async function login() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    if (!username || !password) {
        showError('authError', 'Please enter both username and password');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/admin/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Login failed');
        }

        const data = await response.json();

        if (data.mfaRequired) {
            // MFA is enabled - show MFA form
            AdminConfig.setTempMFAToken(data.tempToken);
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('mfaForm').style.display = 'block';
            document.getElementById('mfaCode').focus();
        } else {
            // No MFA - proceed with login
            completeLogin(data);
        }

    } catch (error) {
        console.error('Login error:', error);
        showError('authError', error.message);
    }
}

// MFA Verification
async function verifyMFA() {
    const mfaCode = document.getElementById('mfaCode').value.trim();

    if (!mfaCode || mfaCode.length !== 6) {
        showError('mfaError', 'Please enter a valid 6-digit code');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/admin/auth/verify-mfa`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tempToken: AdminConfig.getTempMFAToken(),
                mfaCode: mfaCode,
                useBackupCode: false
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'MFA verification failed');
        }

        const data = await response.json();
        completeLogin(data);

    } catch (error) {
        console.error('MFA verification error:', error);
        showError('mfaError', error.message);
        document.getElementById('mfaCode').value = '';
    }
}

// Verify Backup Code
async function verifyBackupCode() {
    const backupCode = document.getElementById('backupCode').value.trim().toUpperCase();

    if (!backupCode) {
        showError('mfaError', 'Please enter a backup code');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/admin/auth/verify-mfa`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tempToken: AdminConfig.getTempMFAToken(),
                mfaCode: backupCode,
                useBackupCode: true
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Backup code verification failed');
        }

        const data = await response.json();
        completeLogin(data);

    } catch (error) {
        console.error('Backup code verification error:', error);
        showError('mfaError', error.message);
    }
}

// Complete login after authentication
function completeLogin(data) {
    AdminConfig.setAuthToken(data.accessToken);
    AdminConfig.setRefreshToken(data.refreshToken);
    AdminConfig.setCurrentUser(data.admin);

    // Store tokens
    localStorage.setItem('jwt_token', data.accessToken);
    localStorage.setItem('refresh_token', data.refreshToken);
    localStorage.setItem('current_user', JSON.stringify(data.admin));

    // Hide auth forms
    document.getElementById('authSection').style.display = 'none';
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('mfaForm').style.display = 'none';

    // Show dashboard
    document.getElementById('mainDashboard').style.display = 'block';

    // Clear form fields
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    document.getElementById('mfaCode').value = '';
    AdminConfig.setTempMFAToken(null);

    // Load data
    loadData();

    console.log('Login successful:', data.admin.username);
}

// Cancel MFA
function cancelMFA() {
    AdminConfig.setTempMFAToken(null);
    document.getElementById('mfaForm').style.display = 'none';
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('mfaCode').value = '';
    document.getElementById('backupCode').value = '';
    document.getElementById('backupCodeInput').style.display = 'none';
}

// Show backup code input
function showBackupCodeInput() {
    document.getElementById('backupCodeInput').style.display = 'block';
    document.getElementById('backupCode').focus();
}

// Logout
async function logout() {
    try {
        if (AdminConfig.getAuthToken()) {
            await fetch(`${API_BASE}/api/admin/auth/logout`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${AdminConfig.getAuthToken()}`
                }
            });
        }
    } catch (error) {
        console.error('Logout error:', error);
    }

    // Clear tokens and state
    AdminConfig.setAuthToken(null);
    AdminConfig.setRefreshToken(null);
    AdminConfig.setCurrentUser(null);
    localStorage.removeItem('jwt_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('current_user');

    // Show login form
    document.getElementById('authSection').style.display = 'block';
    document.getElementById('mainDashboard').style.display = 'none';
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('mfaForm').style.display = 'none';
}

// Refresh Access Token
async function refreshAccessToken() {
    try {
        const response = await fetch(`${API_BASE}/api/admin/auth/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken: AdminConfig.getRefreshToken() })
        });

        if (!response.ok) {
            throw new Error('Token refresh failed');
        }

        const data = await response.json();
        AdminConfig.setAuthToken(data.accessToken);
        localStorage.setItem('jwt_token', data.accessToken);

        console.log('Token refreshed successfully');
        return true;

    } catch (error) {
        console.error('Token refresh error:', error);
        return false;
    }
}
