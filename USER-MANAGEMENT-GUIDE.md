# User Management Guide

## Overview

The Script Integrity Monitor includes comprehensive user management functionality that allows administrators to create, update, enable, disable, and delete admin users with different roles and permissions.

## Features Implemented

### ✅ Add New Users
- Create new admin users with username, email, and password
- Assign roles: Viewer, Reviewer, Admin, or Super Admin
- Set initial active/inactive status

### ✅ Update Users
- Modify username, email, and role
- Change password (optional - leave blank to keep existing)
- Update active/inactive status

### ✅ Enable/Disable Users
- Quickly enable or disable user accounts with one click
- Disabled users cannot log in
- Maintains user data for audit purposes

### ✅ Delete Users
- Permanently remove users from the system
- Confirmation prompt to prevent accidental deletion
- Cannot delete your own account (safety feature)

## User Roles

### Viewer
- **Permissions**: Read-only access
- **Can**: View dashboard, scripts, and violations
- **Cannot**: Approve/reject scripts, modify settings, manage users

### Reviewer
- **Permissions**: Can review and approve scripts
- **Can**: View dashboard, approve/reject pending scripts
- **Cannot**: Modify system settings, manage users

### Admin
- **Permissions**: Full administrative access
- **Can**: Everything Reviewer can do, plus manage users, modify settings
- **Cannot**: Delete own account

### Super Admin
- **Permissions**: Full system access
- **Can**: Everything including critical system operations
- **Note**: Highest level of access

## Using the User Management Interface

### Accessing User Management

1. Log in to the Admin Panel: `http://localhost:3000/admin-panel.html`
2. Click on the **"User Management"** tab in the navigation

### Adding a New User

1. Click **"Add New User"** button
2. Fill in the form:
   - **Username** (required): Unique username for login
   - **Email** (required): User's email address
   - **Password** (required): Initial password
   - **Role**: Select from dropdown (Viewer/Reviewer/Admin/Super Admin)
   - **Status**: Active or Inactive
3. Click **"Save"**
4. User is created immediately and can log in

### Editing an Existing User

1. Find the user in the table
2. Click **"✏️ Edit"** button
3. Modify the fields:
   - Username
   - Email
   - Password (leave blank to keep existing password)
   - Role
   - Status
4. Click **"Save"**
5. Changes take effect immediately

### Enabling/Disabling a User

#### To Disable a User:
1. Find the user in the table (must have "Active" status)
2. Click **"🚫 Disable"** button
3. Confirm the action
4. User status changes to "Inactive"
5. User can no longer log in

#### To Enable a User:
1. Find the user in the table (must have "Inactive" status)
2. Click **"✅ Enable"** button
3. Confirm the action
4. User status changes to "Active"
5. User can log in again

### Deleting a User

1. Find the user in the table
2. Click **"🗑️ Delete"** button
3. Confirm deletion (this action cannot be undone)
4. User is permanently removed from the database

**Note**: You cannot delete your own account - this prevents accidental lockout.

## API Endpoints

### Get All Users
```
GET /api/admin/users
Headers: X-API-Token: <your-token>
Response: { success: true, data: [users...] }
```

### Create New User
```
POST /api/admin/users
Headers:
  X-API-Token: <your-token>
  Content-Type: application/json
Body:
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "SecurePass123!",
  "role": "reviewer",
  "is_active": 1
}
Response: { success: true, data: {user} }
```

### Update User
```
PUT /api/admin/users/:id
Headers:
  X-API-Token: <your-token>
  Content-Type: application/json
Body:
{
  "username": "updateduser",
  "email": "updated@example.com",
  "role": "admin",
  "is_active": 1
}
Response: { success: true, data: {user} }
```

### Delete User
```
DELETE /api/admin/users/:id
Headers: X-API-Token: <your-token>
Response: { success: true, message: "User deleted successfully" }
```

## Security Features

### Password Security
- Passwords are hashed using bcrypt with salt rounds of 10
- Plain text passwords are never stored in the database
- Password field is optional when updating users (keeps existing if blank)

### Account Protection
- Users cannot modify or delete their own account
- Prevents accidental self-lockout
- Current user is clearly marked in the user list

### Role-Based Access Control
- Only Admin and Super Admin roles can access user management
- Each role has specific permissions enforced server-side
- Token-based authentication required for all API calls

### Session Management
- JWT tokens with expiration
- Automatic token refresh
- Session persistence across page reloads

## Database Schema

Users are stored in the `admin_users` table:

```sql
CREATE TABLE admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('viewer', 'reviewer', 'admin', 'super_admin')),
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME,
    -- Additional fields for MFA, tokens, etc.
);
```

## User Interface Features

### User Table Columns
1. **ID**: User's unique identifier
2. **Username**: Login username
3. **Email**: Email address
4. **Role**: Colored badge showing user role
5. **Status**: Green "Active" or Red "Inactive" badge
6. **Created**: Date user was created
7. **Last Login**: Last login timestamp or "Never"
8. **Actions**: Edit, Enable/Disable, Delete buttons

### Status Badges
- **Active**: Green badge
- **Inactive**: Red badge
- **Super Admin**: Purple badge
- **Admin**: Blue badge
- **Reviewer**: Green badge
- **Viewer**: Gray badge

### Responsive Design
- Clean, modern interface
- Clear action buttons with icons
- Confirmation dialogs for destructive actions
- Error messages displayed in modal forms

## Best Practices

### When Creating Users
1. Use strong passwords (12+ characters, mixed case, numbers, symbols)
2. Assign the minimum role needed (principle of least privilege)
3. Use meaningful usernames that identify the person
4. Use real email addresses for account recovery

### When Disabling Users
1. Disable instead of delete when user may return
2. Keeps audit trail intact
3. Can be re-enabled without losing history

### When Deleting Users
1. Only delete when user will never return
2. Ensure no critical operations are tied to that user
3. Export audit logs first if needed for compliance

### Account Management
1. Regularly review active users
2. Disable inactive accounts
3. Enforce periodic password changes
4. Enable MFA for all admin accounts

## Troubleshooting

### Can't See User Management Tab
- Check your role (must be Admin or Super Admin)
- Verify you're logged in
- Check browser console for errors

### Can't Create User
- Verify all required fields are filled
- Check username/email aren't already taken
- Ensure password meets minimum requirements
- Check network console for API errors

### Can't Enable/Disable User
- Verify you have Admin or Super Admin role
- Check you're not trying to modify your own account
- Verify user exists in database

### Changes Not Saving
- Check browser network tab for failed requests
- Verify authentication token is valid
- Check server logs for errors
- Ensure database is writable

## Example Use Cases

### Scenario 1: New Employee Onboarding
1. Click "Add New User"
2. Enter: username=john.doe, email=john@company.com, password=TempPass123!
3. Set role=Reviewer
4. Set status=Active
5. Save
6. Send login credentials to new employee
7. Instruct them to change password on first login

### Scenario 2: Employee Role Change
1. Find user in table
2. Click "Edit"
3. Change role from "Reviewer" to "Admin"
4. Click "Save"
5. User now has Admin permissions on next login

### Scenario 3: Employee Departure
1. Find user in table
2. Click "Disable" (not Delete initially)
3. Confirm
4. User can no longer log in
5. After retention period, click "Delete" to remove permanently

### Scenario 4: Temporary Access Suspension
1. Find user in table
2. Click "Disable"
3. User account suspended
4. When ready to restore access, click "Enable"
5. User can log in again

## Compliance & Audit

### Audit Trail
- User creation logged with timestamp
- Role changes tracked
- Last login times recorded
- Account status changes logged

### PCI DSS Considerations
- User access controls required
- Least privilege principle enforced
- Account review capability
- Disable inactive accounts

### Data Retention
- User records maintained for audit purposes
- Deletion requires explicit confirmation
- Account history preserved in related tables

## API Code Examples

### JavaScript (Fetch API)

```javascript
// Get all users
async function getAllUsers(token) {
  const response = await fetch('/api/admin/users', {
    headers: { 'X-API-Token': token }
  });
  return await response.json();
}

// Create new user
async function createUser(token, userData) {
  const response = await fetch('/api/admin/users', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Token': token
    },
    body: JSON.stringify(userData)
  });
  return await response.json();
}

// Update user
async function updateUser(token, userId, updates) {
  const response = await fetch(`/api/admin/users/${userId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Token': token
    },
    body: JSON.stringify(updates)
  });
  return await response.json();
}

// Delete user
async function deleteUser(token, userId) {
  const response = await fetch(`/api/admin/users/${userId}`, {
    method: 'DELETE',
    headers: { 'X-API-Token': token }
  });
  return await response.json();
}
```

### cURL Examples

```bash
# Get all users
curl -H "X-API-Token: your-token" \
  http://localhost:3000/api/admin/users

# Create new user
curl -X POST \
  -H "X-API-Token: your-token" \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser","email":"new@example.com","password":"Pass123!","role":"reviewer","is_active":1}' \
  http://localhost:3000/api/admin/users

# Update user (enable/disable)
curl -X PUT \
  -H "X-API-Token: your-token" \
  -H "Content-Type: application/json" \
  -d '{"is_active":0}' \
  http://localhost:3000/api/admin/users/2

# Delete user
curl -X DELETE \
  -H "X-API-Token: your-token" \
  http://localhost:3000/api/admin/users/2
```

## Future Enhancements (Optional)

1. **Bulk Operations**: Enable/disable multiple users at once
2. **User Groups**: Organize users into teams or departments
3. **Activity Log**: Detailed log of all user actions
4. **Password Policies**: Enforce complexity and expiration
5. **Email Verification**: Verify email addresses on registration
6. **Account Recovery**: Self-service password reset via email
7. **User Import/Export**: Bulk user management via CSV
8. **Permission Granularity**: Fine-grained permission controls

## Support

For issues or questions about user management:
1. Check server logs for API errors
2. Check browser console for client-side errors
3. Verify database integrity
4. Review this guide for proper usage

## Summary

The user management system provides complete CRUD (Create, Read, Update, Delete) operations for admin users with:
- ✅ Intuitive web interface
- ✅ Role-based access control
- ✅ Enable/disable functionality
- ✅ Security best practices
- ✅ Comprehensive API
- ✅ Audit trail support

Access the user management interface at:
**http://localhost:3000/admin-panel.html** → **User Management** tab
