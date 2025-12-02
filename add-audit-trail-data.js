const { DatabaseManager } = require('./database-manager');

async function addAuditTrailData() {
  const db = new DatabaseManager();
  await db.initialize();

  console.log('Adding test audit trail data...');

  const auditEntries = [
    // Script approvals
    {
      username: 'admin',
      action_type: 'script_approved',
      action_description: 'Approved jquery-3.6.0.min.js for production use',
      entity_type: 'script',
      entity_id: '1',
      action_reason: 'Well-known library, verified hash matches official CDN',
      success: 1
    },
    {
      username: 'admin',
      action_type: 'script_approved',
      action_description: 'Approved payment-widget.js for checkout page',
      entity_type: 'script',
      entity_id: '2',
      action_reason: 'Payment processor required script, vendor verified',
      success: 1
    },
    // Script rejections
    {
      username: 'admin',
      action_type: 'script_rejected',
      action_description: 'Rejected suspicious-analytics.js',
      entity_type: 'script',
      entity_id: '3',
      action_reason: 'Unauthorized third-party tracking script',
      success: 1
    },
    {
      username: 'admin',
      action_type: 'script_rejected',
      action_description: 'Rejected malware-loader.js',
      entity_type: 'script',
      entity_id: '4',
      action_reason: 'Detected malicious code injection attempt',
      success: 1
    },
    // Script deletions
    {
      username: 'admin',
      action_type: 'script_deleted',
      action_description: 'Deleted old-jquery-2.1.0.min.js',
      entity_type: 'script',
      entity_id: '5',
      action_reason: 'Outdated library with known security vulnerabilities',
      success: 1
    },
    // Bulk operations
    {
      username: 'admin',
      action_type: 'scripts_bulk_deleted',
      action_description: 'Bulk deleted 3 outdated scripts',
      entity_type: 'script',
      entity_id: 'bulk-456',
      action_reason: 'Cleanup of deprecated dependencies',
      success: 1
    },
    // User management
    {
      username: 'admin',
      action_type: 'user_created',
      action_description: 'Created new admin user: security-team',
      entity_type: 'user',
      entity_id: '2',
      action_reason: 'New security team member onboarding',
      success: 1
    },
    {
      username: 'admin',
      action_type: 'user_updated',
      action_description: 'Updated user permissions for security-team',
      entity_type: 'user',
      entity_id: '2',
      action_reason: 'Granted violation review permissions',
      success: 1
    },
    // Failed actions
    {
      username: 'admin',
      action_type: 'script_approved',
      action_description: 'Failed to approve invalid-script.js',
      entity_type: 'script',
      entity_id: '999',
      action_reason: 'Attempted to approve script',
      error_message: 'Script not found in database',
      success: 0
    },
    {
      username: 'admin',
      action_type: 'script_deleted',
      action_description: 'Failed to delete protected script',
      entity_type: 'script',
      entity_id: '1',
      action_reason: 'Attempted cleanup',
      error_message: 'Cannot delete currently approved script',
      success: 0
    },
    // Configuration changes
    {
      username: 'admin',
      action_type: 'settings_updated',
      action_description: 'Updated alert threshold settings',
      entity_type: 'settings',
      entity_id: 'alert_config',
      action_reason: 'Increased sensitivity for payment page monitoring',
      success: 1
    },
    // Violation reviews
    {
      username: 'admin',
      action_type: 'violation_reviewed',
      action_description: 'Reviewed integrity violation for checkout.js',
      entity_type: 'violation',
      entity_id: '10',
      action_reason: 'Confirmed false positive - CDN cache update',
      success: 1
    },
    {
      username: 'admin',
      action_type: 'violation_reviewed',
      action_description: 'Reviewed hash mismatch violation',
      entity_type: 'violation',
      entity_id: '11',
      action_reason: 'Confirmed security incident - escalated to security team',
      success: 1
    }
  ];

  // Insert entries with timestamp variation (spread over last 30 days)
  for (let i = 0; i < auditEntries.length; i++) {
    const entry = auditEntries[i];
    const daysAgo = Math.floor(i * 2); // Spread over 28 days
    const timestamp = new Date(Date.now() - (daysAgo * 24 * 60 * 60 * 1000)).toISOString();

    await db.query(
      `INSERT INTO audit_trail
       (username, action_type, action_description, entity_type, entity_id, action_reason, error_message, success, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        entry.username,
        entry.action_type,
        entry.action_description,
        entry.entity_type,
        entry.entity_id,
        entry.action_reason,
        entry.error_message || null,
        entry.success,
        timestamp
      ]
    );
  }

  console.log(`✓ Added ${auditEntries.length} audit trail entries`);

  await db.close();
}

addAuditTrailData().catch(console.error);
