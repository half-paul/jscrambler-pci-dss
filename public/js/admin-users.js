/**
 * User Management Module
 * Handles user CRUD operations and user management UI
 */

// USER MANAGEMENT FUNCTIONS
// ============================================================================

let currentEditingUserId = null;

/**
 * Load and display all users
 */
async function loadUsers() {
    try {
        const response = await fetch('/api/admin/users', {
            headers: {
                'X-API-Token': authToken
            }
        });

        if (!response.ok) {
            if (response.status === 401) {
                handleTokenExpiration();
                return;
            }
            throw new Error('Failed to load users');
        }

        const data = await response.json();
        const users = data.data || [];

        displayUsers(users);
    } catch (error) {
        console.error('[Users] Error loading users:', error);
        document.getElementById('usersContent').innerHTML = `
            <div class="error-message" style="display: block;">
                Failed to load users: ${error.message}
            </div>
        `;
    }
}

/**
 * Display users in a table
 */
function displayUsers(users) {
    const container = document.getElementById('usersContent');

    if (users.length === 0) {
        container.innerHTML = '<p style="color: #7f8c8d;">No users found.</p>';
        return;
    }

    let html = `
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Last Login</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;

    users.forEach(user => {
        const isActive = user.is_active === 1 || user.is_active === true;
        const statusBadge = isActive
            ? '<span class="status-badge approved">Active</span>'
            : '<span class="status-badge rejected">Inactive</span>';

        const roleBadge = {
            'super_admin': '<span class="status-badge" style="background: #9b59b6;">Super Admin</span>',
            'admin': '<span class="status-badge" style="background: #3498db;">Admin</span>',
            'reviewer': '<span class="status-badge" style="background: #2ecc71;">Reviewer</span>',
            'viewer': '<span class="status-badge" style="background: #95a5a6;">Viewer</span>'
        }[user.role] || user.role;

        const createdDate = new Date(user.created_at).toLocaleDateString();
        const lastLogin = user.last_login_at ? new Date(user.last_login_at).toLocaleString() : 'Never';

        const isCurrentUser = currentUser && (currentUser.id === user.id || currentUser.username === user.username);
        const canModify = !isCurrentUser; // Can't modify own account

        html += `
            <tr>
                <td>${user.id}</td>
                <td><strong>${escapeHtml(user.username)}</strong></td>
                <td>${escapeHtml(user.email)}</td>
                <td>${roleBadge}</td>
                <td>${statusBadge}</td>
                <td>${createdDate}</td>
                <td style="font-size: 12px;">${lastLogin}</td>
                <td>
                    ${canModify ? `
                        <button class="small secondary" onclick="editUser(${user.id})" title="Edit User">
                            ✏️ Edit
                        </button>
                        ${isActive ? `
                            <button class="small danger" onclick="toggleUserStatus(${user.id}, false)" title="Disable User">
                                🚫 Disable
                            </button>
                        ` : `
                            <button class="small success" onclick="toggleUserStatus(${user.id}, true)" title="Enable User">
                                ✅ Enable
                            </button>
                        `}
                        <button class="small danger" onclick="confirmDeleteUser(${user.id}, '${escapeHtml(user.username)}')" title="Delete User">
                            🗑️ Delete
                        </button>
                    ` : '<span style="color: #95a5a6; font-size: 12px;">(Current User)</span>'}
                </td>
            </tr>
        `;
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

/**
 * Open user modal for adding a new user
 */
function openUserModal() {
    currentEditingUserId = null;
    document.getElementById('userModalTitle').textContent = 'Add New User';
    document.getElementById('userUsername').value = '';
    document.getElementById('userEmail').value = '';
    document.getElementById('userPassword').value = '';
    document.getElementById('userPassword').required = true;
    document.getElementById('userPassword').parentElement.querySelector('label').textContent = 'Password *';
    document.getElementById('userRole').value = 'reviewer';
    document.getElementById('userIsActive').value = '1';
    document.getElementById('userError').style.display = 'none';
    document.getElementById('userModal').style.display = 'flex';
}

/**
 * Edit an existing user
 */
async function editUser(userId) {
    try {
        const response = await fetch('/api/admin/users', {
            headers: {
                'X-API-Token': authToken
            }
        });

        if (!response.ok) throw new Error('Failed to load user data');

        const data = await response.json();
        const user = (data.data || []).find(u => u.id === userId);

        if (!user) {
            alert('User not found');
            return;
        }

        currentEditingUserId = userId;
        document.getElementById('userModalTitle').textContent = 'Edit User';
        document.getElementById('userUsername').value = user.username;
        document.getElementById('userEmail').value = user.email;
        document.getElementById('userPassword').value = '';
        document.getElementById('userPassword').required = false;
        document.getElementById('userPassword').parentElement.querySelector('label').textContent = 'Password (leave blank to keep unchanged)';
        document.getElementById('userRole').value = user.role;
        document.getElementById('userIsActive').value = user.is_active ? '1' : '0';
        document.getElementById('userError').style.display = 'none';
        document.getElementById('userModal').style.display = 'flex';
    } catch (error) {
        console.error('[Users] Error loading user for edit:', error);
        alert('Failed to load user data: ' + error.message);
    }
}

/**
 * Save user (create or update)
 */
async function saveUser() {
    const username = document.getElementById('userUsername').value.trim();
    const email = document.getElementById('userEmail').value.trim();
    const password = document.getElementById('userPassword').value;
    const role = document.getElementById('userRole').value;
    const is_active = parseInt(document.getElementById('userIsActive').value);

    // Validation
    if (!username || !email) {
        showUserError('Username and email are required');
        return;
    }

    if (!currentEditingUserId && !password) {
        showUserError('Password is required for new users');
        return;
    }

    const userData = {
        username,
        email,
        role,
        is_active
    };

    if (password) {
        userData.password = password;
    }

    try {
        const url = currentEditingUserId
            ? `/api/admin/users/${currentEditingUserId}`
            : '/api/admin/users';

        const method = currentEditingUserId ? 'PUT' : 'POST';

        const response = await fetch(url, {
            method,
            headers: {
                'Content-Type': 'application/json',
                'X-API-Token': authToken
            },
            body: JSON.stringify(userData)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to save user');
        }

        closeUserModal();
        loadUsers();

        const action = currentEditingUserId ? 'updated' : 'created';
        alert(`User ${action} successfully`);
    } catch (error) {
        console.error('[Users] Error saving user:', error);
        showUserError(error.message);
    }
}

/**
 * Toggle user status (enable/disable)
 */
async function toggleUserStatus(userId, enable) {
    const action = enable ? 'enable' : 'disable';

    if (!confirm(`Are you sure you want to ${action} this user?`)) {
        return;
    }

    try {
        const response = await fetch(`/api/admin/users/${userId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Token': authToken
            },
            body: JSON.stringify({
                is_active: enable ? 1 : 0
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || `Failed to ${action} user`);
        }

        loadUsers();
        alert(`User ${enable ? 'enabled' : 'disabled'} successfully`);
    } catch (error) {
        console.error(`[Users] Error ${action}ing user:`, error);
        alert(`Failed to ${action} user: ${error.message}`);
    }
}

/**
 * Confirm and delete a user
 */
function confirmDeleteUser(userId, username) {
    if (!confirm(`Are you sure you want to DELETE user "${username}"?\n\nThis action cannot be undone!`)) {
        return;
    }

    deleteUserById(userId);
}

/**
 * Delete a user by ID
 */
async function deleteUserById(userId) {
    try {
        const response = await fetch(`/api/admin/users/${userId}`, {
            method: 'DELETE',
            headers: {
                'X-API-Token': authToken
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to delete user');
        }

        loadUsers();
        alert('User deleted successfully');
    } catch (error) {
        console.error('[Users] Error deleting user:', error);
        alert('Failed to delete user: ' + error.message);
    }
}

/**
 * Close user modal
 */
function closeUserModal() {
    document.getElementById('userModal').style.display = 'none';
    currentEditingUserId = null;
}

/**
 * Show error in user modal
 */
function showUserError(message) {
    const errorDiv = document.getElementById('userError');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
}

/**
 * HTML escape helper
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ======================
// Audit Trail Functions
// ======================

let currentAuditPage = 1;
const auditPageSize = 50;

/**
 * Load audit trail with filters and pagination
 */
