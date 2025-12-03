/**
 * MFA Management Module
 * Handles two-factor authentication setup, verification, and management
 */

async function updateMfaStatus() {
    if (!currentUser) return;

    try {
        // Get current MFA status from user object or make API call
        const mfaEnabled = currentUser.mfa_enabled || false;

        const statusText = document.getElementById('mfaStatusText');
        const statusBadge = document.getElementById('mfaStatusBadge');
        const enableBtn = document.getElementById('enableMfaBtn');
        const disableBtn = document.getElementById('disableMfaBtn');

        if (mfaEnabled) {
            statusText.textContent = 'Enabled';
            statusText.style.color = '#27ae60';
            statusBadge.innerHTML = '<span class="badge approved">Enabled</span>';
            enableBtn.style.display = 'none';
            disableBtn.style.display = 'inline-block';
        } else {
            statusText.textContent = 'Disabled';
            statusText.style.color = '#e74c3c';
            statusBadge.innerHTML = '<span class="badge rejected">Disabled</span>';
            enableBtn.style.display = 'inline-block';
            disableBtn.style.display = 'none';
        }
    } catch (error) {
        console.error('Error updating MFA status:', error);
    }
}

function updateAccountInfo() {
    if (!currentUser) return;

    document.getElementById('accountUsername').textContent = currentUser.username || '-';
    document.getElementById('accountEmail').textContent = currentUser.email || '-';
    document.getElementById('accountRole').textContent = currentUser.role || '-';
}

let mfaSetupData = null;

async function startMfaSetup() {
    try {
        document.getElementById('mfaSetupError').style.display = 'none';
        document.getElementById('mfaSetupSuccess').style.display = 'none';

        // Show modal first (so elements are in DOM)
        document.getElementById('mfaSetupStep1').style.display = 'block';
        document.getElementById('mfaSetupStep2').style.display = 'none';
        document.getElementById('mfaSetupModal').classList.add('active');

        // Call API to generate MFA secret and QR code
        const data = await apiCall('/api/admin/auth/setup-mfa', {
            method: 'POST',
            body: JSON.stringify({ action: 'generate' })
        });

        mfaSetupData = data;

        // Now set QR code and secret (elements are visible)
        document.getElementById('mfaQrCode').src = data.qrCode;
        document.getElementById('mfaSecretKey').textContent = data.secret;
        document.getElementById('mfaVerificationCode').value = '';

        document.getElementById('mfaVerificationCode').focus();

    } catch (error) {
        console.error('MFA setup error:', error);
        document.getElementById('mfaSetupError').textContent = 'Failed to start MFA setup: ' + error.message;
        document.getElementById('mfaSetupError').style.display = 'block';
        // Close modal on error
        closeMfaSetupModal();
    }
}

async function verifyMfaSetup() {
    const verificationCode = document.getElementById('mfaVerificationCode').value.trim();

    if (!verificationCode || verificationCode.length !== 6) {
        document.getElementById('mfaSetupModalError').textContent = 'Please enter a valid 6-digit code';
        document.getElementById('mfaSetupModalError').style.display = 'block';
        return;
    }

    try {
        document.getElementById('mfaSetupModalError').style.display = 'none';

        // Verify and enable MFA
        const data = await apiCall('/api/admin/auth/setup-mfa', {
            method: 'POST',
            body: JSON.stringify({
                action: 'verify',
                verificationCode: verificationCode
            })
        });

        // Update current user MFA status
        currentUser.mfa_enabled = true;
        localStorage.setItem('current_user', JSON.stringify(currentUser));

        // Show backup codes
        const backupCodesHtml = data.backupCodes.map(code =>
            `<div style="padding: 8px; background: #fff; border: 1px solid #ddd; border-radius: 4px; text-align: center;">${code}</div>`
        ).join('');
        document.getElementById('backupCodesList').innerHTML = backupCodesHtml;

        // Show step 2 (backup codes)
        document.getElementById('mfaSetupStep1').style.display = 'none';
        document.getElementById('mfaSetupStep2').style.display = 'block';

        // Update status in main UI
        updateMfaStatus();

    } catch (error) {
        console.error('MFA verification error:', error);
        document.getElementById('mfaSetupModalError').textContent = 'Verification failed: ' + error.message;
        document.getElementById('mfaSetupModalError').style.display = 'block';
        document.getElementById('mfaVerificationCode').value = '';
    }
}

function copyBackupCodes() {
    const codes = document.getElementById('backupCodesList').innerText;
    navigator.clipboard.writeText(codes).then(() => {
        alert('Backup codes copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

function closeMfaSetupModal() {
    document.getElementById('mfaSetupModal').classList.remove('active');
    document.getElementById('mfaSetupStep1').style.display = 'none';
    document.getElementById('mfaSetupStep2').style.display = 'none';
    document.getElementById('mfaSetupModalError').style.display = 'none';
    mfaSetupData = null;
}

async function disableMfa() {
    const verificationCode = prompt('To disable MFA, please enter a verification code from your authenticator app:');
    if (!verificationCode) {
        return;
    }

    if (!confirm('Are you sure you want to disable Two-Factor Authentication? This will make your account less secure.')) {
        return;
    }

    try {
        await apiCall('/api/admin/auth/setup-mfa', {
            method: 'POST',
            body: JSON.stringify({ action: 'disable', verificationCode: verificationCode })
        });

        // Update current user MFA status
        currentUser.mfa_enabled = false;
        localStorage.setItem('current_user', JSON.stringify(currentUser));

        // Update status
        updateMfaStatus();

        document.getElementById('mfaSetupSuccess').textContent = 'Two-Factor Authentication has been disabled.';
        document.getElementById('mfaSetupSuccess').style.display = 'block';

        setTimeout(() => {
            document.getElementById('mfaSetupSuccess').style.display = 'none';
        }, 5000);

    } catch (error) {
        console.error('MFA disable error:', error);
        document.getElementById('mfaSetupError').textContent = 'Failed to disable MFA: ' + error.message;
        document.getElementById('mfaSetupError').style.display = 'block';
    }
}

// Auto-refresh every 30 seconds
setInterval(() => {
    if (authToken) {
        loadData();
    }
}, 30000);

// Check if already logged in on page load
if (authToken && refreshToken) {
    // Try to restore session from localStorage
    const savedUser = localStorage.getItem('current_user');
    if (savedUser) {
        try {
            currentUser = JSON.parse(savedUser);
        } catch (e) {
            console.error('Failed to parse saved user:', e);
        }
    }

    // Test the token and show dashboard if valid
    fetchDashboard().then(() => {
        document.getElementById('authSection').style.display = 'none';
        document.getElementById('mainDashboard').style.display = 'block';
        loadData();
        console.log('Session restored for:', currentUser?.username || 'unknown user');
    }).catch(err => {
        // Token expired or invalid - try to refresh
        refreshAccessToken().then(refreshed => {
            if (refreshed) {
                // Retry loading dashboard with new token
                fetchDashboard().then(() => {
                    document.getElementById('authSection').style.display = 'none';
                    document.getElementById('mainDashboard').style.display = 'block';
                    loadData();
                }).catch(() => {
                    // Still failed, clear and show login
                    logout();
                });
            } else {
                // Refresh failed, show login
                logout();
            }
        }).catch(() => {
            logout();
        });
    });
}

document.getElementById('loginButton').addEventListener('click', login);

// Enable Enter key to submit login form
document.getElementById('username').addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        login();
    }
});

document.getElementById('password').addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        login();
    }
});

// Enable Enter key for MFA code input
document.getElementById('mfaCode').addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        verifyMFA();
    }
});

// Enable Enter key for backup code input
document.getElementById('backupCode').addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        verifyBackupCode();
    }
});

