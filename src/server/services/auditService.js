/**
 * Audit Trail Service
 * Centralized audit logging for all admin actions
 *
 * PCI DSS v4.0 Requirement: 7-year audit trail retention for compliance
 */

const crypto = require('crypto');

/**
 * Create audit logging function with database instance
 * @param {Object} db - Database instance
 * @returns {Function} logAudit function
 */
function createAuditService(db) {
  /**
   * Log an action to the audit trail
   * @param {Object} options - Audit log options
   * @param {Object} options.req - Express request object (for IP, user-agent, etc.)
   * @param {Object} options.admin - Admin user object (from req.admin)
   * @param {string} options.actionType - Type of action (must match CHECK constraint in schema)
   * @param {string} options.entityType - Type of entity acted upon
   * @param {string|string[]} options.entityId - ID(s) of entity (can be array for bulk)
   * @param {string} options.actionDescription - Human-readable description
   * @param {string} [options.actionReason] - Optional reason provided by user
   * @param {Object} [options.oldValues] - Old values (for updates)
   * @param {Object} [options.newValues] - New values (for updates)
   * @param {boolean} [options.success=true] - Whether action succeeded
   * @param {string} [options.errorMessage] - Error message if failed
   */
  async function logAudit(options) {
    try {
      const {
        req,
        admin,
        actionType,
        entityType,
        entityId,
        actionDescription,
        actionReason,
        oldValues,
        newValues,
        success = true,
        errorMessage
      } = options;

      // Handle bulk entity IDs
      const entityIdStr = Array.isArray(entityId) ? entityId.join(',') : String(entityId || '');
      const entityCount = Array.isArray(entityId) ? entityId.length : 1;

      // Hash IP address for privacy
      const ipAddress = req?.ip || req?.connection?.remoteAddress || '';
      const hashedIp = ipAddress ? crypto.createHash('sha256')
        .update(ipAddress + (process.env.IP_SALT || 'default-salt'))
        .digest('hex').substring(0, 64) : null;

      // Calculate retention date (12 months retention policy)
      const retentionDate = new Date();
      retentionDate.setMonth(retentionDate.getMonth() + 12);

      await db.query(
        `INSERT INTO audit_trail (
          timestamp, user_id, username, user_role,
          action_type, entity_type, entity_id, entity_count,
          action_description, action_reason,
          ip_address, user_agent, request_method, request_path,
          old_values, new_values,
          success, error_message, retention_until
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          new Date().toISOString(),
          admin?.id || null,
          admin?.username || 'system',
          admin?.role || null,
          actionType,
          entityType,
          entityIdStr,
          entityCount,
          actionDescription,
          actionReason || null,
          hashedIp,
          req?.headers['user-agent'] || null,
          req?.method || null,
          req?.path || null,
          oldValues ? JSON.stringify(oldValues) : null,
          newValues ? JSON.stringify(newValues) : null,
          success ? 1 : 0,
          errorMessage || null,
          retentionDate.toISOString()
        ]
      );

      console.log(`[Audit] ${actionType} by ${admin?.username || 'system'}: ${actionDescription}`);
    } catch (error) {
      // Don't fail the main operation if audit logging fails
      console.error('[Audit] Failed to log audit trail:', error.message);
    }
  }

  return { logAudit };
}

module.exports = { createAuditService };
