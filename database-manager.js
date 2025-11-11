/**
 * Database Manager - Abstraction Layer
 * PCI DSS v4.0 Requirement 6.4.3 Compliance
 *
 * Provides database abstraction supporting both SQLite (development)
 * and PostgreSQL (production) with automatic migration support.
 *
 * Features:
 * - Connection pooling
 * - Transaction support
 * - Prepared statements (SQL injection prevention)
 * - Automatic schema migration
 * - Query logging for audit trail
 *
 * @version 1.0.0
 */

'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Database Manager Class
 * Abstracts database operations across SQLite and PostgreSQL
 */
class DatabaseManager {
  constructor(config = {}) {
    this.config = {
      type: config.type || process.env.DB_TYPE || 'sqlite', // 'sqlite' or 'postgres'

      // SQLite configuration
      sqlitePath: config.sqlitePath || process.env.SQLITE_PATH || './data/integrity-monitor.db',

      // PostgreSQL configuration
      pgHost: config.pgHost || process.env.PG_HOST || 'localhost',
      pgPort: config.pgPort || process.env.PG_PORT || 5432,
      pgDatabase: config.pgDatabase || process.env.PG_DATABASE || 'script_integrity',
      pgUser: config.pgUser || process.env.PG_USER || 'postgres',
      pgPassword: config.pgPassword || process.env.PG_PASSWORD || '',
      pgSsl: config.pgSsl || process.env.PG_SSL === 'true',

      // Connection pool settings
      poolMin: config.poolMin || 2,
      poolMax: config.poolMax || 10,

      // Logging
      logQueries: config.logQueries !== false,

      // Schema
      schemaFile: config.schemaFile || path.join(__dirname, 'database-schema.sql')
    };

    this.db = null;
    this.isConnected = false;
  }

  /**
   * Initialize database connection and schema
   */
  async initialize() {
    console.log(`[DB] Initializing ${this.config.type} database...`);

    try {
      if (this.config.type === 'sqlite') {
        await this.initializeSQLite();
      } else if (this.config.type === 'postgres') {
        await this.initializePostgreSQL();
      } else {
        throw new Error(`Unsupported database type: ${this.config.type}`);
      }

      // Run migrations
      await this.runMigrations();

      this.isConnected = true;
      console.log('[DB] Database initialized successfully');

      return this;
    } catch (error) {
      console.error('[DB] Initialization failed:', error.message);
      throw error;
    }
  }

  /**
   * Initialize SQLite database
   */
  async initializeSQLite() {
    const Database = require('better-sqlite3');

    // Ensure data directory exists
    const dbDir = path.dirname(this.config.sqlitePath);
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }

    // Create database connection
    this.db = new Database(this.config.sqlitePath, {
      verbose: this.config.logQueries ? console.log : null
    });

    // Enable foreign keys
    this.db.pragma('foreign_keys = ON');

    // Enable WAL mode for better concurrency
    this.db.pragma('journal_mode = WAL');

    console.log(`[DB] SQLite database opened at ${this.config.sqlitePath}`);
  }

  /**
   * Initialize PostgreSQL database
   */
  async initializePostgreSQL() {
    const { Pool } = require('pg');

    this.db = new Pool({
      host: this.config.pgHost,
      port: this.config.pgPort,
      database: this.config.pgDatabase,
      user: this.config.pgUser,
      password: this.config.pgPassword,
      ssl: this.config.pgSsl ? { rejectUnauthorized: false } : false,
      min: this.config.poolMin,
      max: this.config.poolMax,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000
    });

    // Test connection
    const client = await this.db.connect();
    await client.query('SELECT NOW()');
    client.release();

    console.log(`[DB] PostgreSQL connected to ${this.config.pgHost}:${this.config.pgPort}/${this.config.pgDatabase}`);
  }

  /**
   * Run database migrations
   */
  async runMigrations() {
    console.log('[DB] Running migrations...');

    try {
      // Read schema file
      const schema = fs.readFileSync(this.config.schemaFile, 'utf8');

      // Execute schema
      if (this.config.type === 'sqlite') {
        this.db.exec(schema);
      } else {
        await this.db.query(schema);
      }

      console.log('[DB] Migrations completed');
    } catch (error) {
      console.error('[DB] Migration failed:', error.message);
      throw error;
    }
  }

  /**
   * Execute a query with parameters
   * @param {string} sql - SQL query
   * @param {Array} params - Query parameters
   * @returns {Promise<Object>} Query result
   */
  async query(sql, params = []) {
    if (!this.isConnected) {
      throw new Error('Database not connected');
    }

    if (this.config.logQueries) {
      console.log('[DB Query]', sql, params);
    }

    try {
      if (this.config.type === 'sqlite') {
        return this.querySQLite(sql, params);
      } else {
        return await this.queryPostgreSQL(sql, params);
      }
    } catch (error) {
      console.error('[DB Error]', error.message);
      console.error('[DB Query]', sql);
      throw error;
    }
  }

  /**
   * Execute SQLite query
   */
  querySQLite(sql, params) {
    const stmt = this.db.prepare(sql);

    // Determine query type
    const isSelect = sql.trim().toUpperCase().startsWith('SELECT');
    const isInsert = sql.trim().toUpperCase().startsWith('INSERT');

    if (isSelect) {
      return stmt.all(params);
    } else if (isInsert) {
      const info = stmt.run(params);
      return {
        rows: [],
        rowCount: info.changes,
        lastInsertRowid: info.lastInsertRowid
      };
    } else {
      const info = stmt.run(params);
      return {
        rows: [],
        rowCount: info.changes
      };
    }
  }

  /**
   * Execute PostgreSQL query
   */
  async queryPostgreSQL(sql, params) {
    const result = await this.db.query(sql, params);

    return {
      rows: result.rows,
      rowCount: result.rowCount
    };
  }

  /**
   * Execute query and return first row
   */
  async queryOne(sql, params = []) {
    const result = await this.query(sql, params);
    return result.rows ? result.rows[0] : result[0];
  }

  /**
   * Begin transaction
   */
  async beginTransaction() {
    if (this.config.type === 'sqlite') {
      this.db.exec('BEGIN TRANSACTION');
      return {
        commit: () => this.db.exec('COMMIT'),
        rollback: () => this.db.exec('ROLLBACK')
      };
    } else {
      const client = await this.db.connect();
      await client.query('BEGIN');
      return {
        query: (sql, params) => client.query(sql, params),
        commit: async () => {
          await client.query('COMMIT');
          client.release();
        },
        rollback: async () => {
          await client.query('ROLLBACK');
          client.release();
        }
      };
    }
  }

  /**
   * Register a new script (auto-discovery)
   */
  async registerScript(scriptData) {
    const {
      url,
      contentHash,
      scriptType,
      sizeBytes,
      contentPreview,
      pageUrl,
      discoveryContext
    } = scriptData;

    // Check if script already exists
    const existing = await this.queryOne(
      'SELECT id, status FROM scripts WHERE url = ? AND content_hash = ?',
      [url, contentHash]
    );

    if (existing) {
      // Update last_seen
      await this.query(
        'UPDATE scripts SET last_seen = CURRENT_TIMESTAMP WHERE id = ?',
        [existing.id]
      );
      return {
        scriptId: existing.id,
        status: existing.status,
        isNew: false
      };
    }

    // Insert new script
    const result = await this.query(
      `INSERT INTO scripts (
        url, content_hash, script_type, size_bytes, content_preview,
        page_url, discovery_context, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_approval')`,
      [url, contentHash, scriptType, sizeBytes, contentPreview, pageUrl, discoveryContext]
    );

    return {
      scriptId: result.lastInsertRowid || result.rows[0]?.id,
      status: 'pending_approval',
      isNew: true
    };
  }

  /**
   * Log integrity violation
   */
  async logViolation(violationData) {
    const {
      scriptId,
      scriptUrl,
      oldHash,
      newHash,
      violationType,
      pageUrl,
      userSession,
      userAgent,
      ipAddress,
      severity,
      actionTaken,
      loadType,
      context
    } = violationData;

    const result = await this.query(
      `INSERT INTO integrity_violations (
        script_id, script_url, old_hash, new_hash, violation_type,
        page_url, user_session, user_agent, ip_address, severity,
        action_taken, load_type, context
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        scriptId || null,
        scriptUrl,
        oldHash || null,
        newHash,
        violationType,
        pageUrl,
        userSession || null,
        userAgent || null,
        ipAddress || null,
        severity,
        actionTaken || 'REPORTED',
        loadType || null,
        context || null
      ]
    );

    return result.lastInsertRowid || result.rows[0]?.id;
  }

  /**
   * Get script status by hash
   */
  async getScriptStatus(contentHash) {
    const script = await this.queryOne(
      'SELECT id, url, status, approved_at FROM scripts WHERE content_hash = ? ORDER BY last_seen DESC LIMIT 1',
      [contentHash]
    );

    return script;
  }

  /**
   * Get pending approvals
   */
  async getPendingApprovals(limit = 50, offset = 0) {
    const scripts = await this.query(
      `SELECT * FROM v_pending_approvals LIMIT ? OFFSET ?`,
      [limit, offset]
    );

    return scripts.rows || scripts;
  }

  /**
   * Approve script
   */
  async approveScript(scriptId, approvalData) {
    const {
      approvedBy,
      businessJustification,
      scriptPurpose,
      scriptOwner,
      riskLevel,
      approvalNotes
    } = approvalData;

    const result = await this.query(
      `UPDATE scripts SET
        status = 'approved',
        approved_by = ?,
        approved_at = CURRENT_TIMESTAMP,
        business_justification = ?,
        script_purpose = ?,
        script_owner = ?,
        risk_level = ?,
        approval_notes = ?
      WHERE id = ?`,
      [approvedBy, businessJustification, scriptPurpose, scriptOwner, riskLevel, approvalNotes, scriptId]
    );

    return result.rowCount > 0;
  }

  /**
   * Reject script
   */
  async rejectScript(scriptId, rejectionData) {
    const { rejectedBy, rejectionReason, notes } = rejectionData;

    const result = await this.query(
      `UPDATE scripts SET
        status = 'rejected',
        approved_by = ?,
        approved_at = CURRENT_TIMESTAMP,
        rejection_reason = ?,
        approval_notes = ?
      WHERE id = ?`,
      [rejectedBy, rejectionReason, notes, scriptId]
    );

    return result.rowCount > 0;
  }

  /**
   * Get recent violations
   */
  async getRecentViolations(limit = 50, offset = 0) {
    const violations = await this.query(
      `SELECT * FROM v_recent_violations LIMIT ? OFFSET ?`,
      [limit, offset]
    );

    return violations.rows || violations;
  }

  /**
   * Get compliance summary
   */
  async getComplianceSummary() {
    const summary = await this.queryOne('SELECT * FROM v_compliance_summary');
    return summary;
  }

  /**
   * Get violation statistics
   */
  async getViolationStatistics() {
    const stats = await this.queryOne('SELECT * FROM v_violation_statistics');
    return stats;
  }

  /**
   * Search scripts
   */
  async searchScripts(searchParams) {
    const { query, status, scriptType, limit = 50, offset = 0 } = searchParams;

    let sql = 'SELECT * FROM scripts WHERE 1=1';
    const params = [];

    if (query) {
      sql += ' AND (url LIKE ? OR content_preview LIKE ?)';
      params.push(`%${query}%`, `%${query}%`);
    }

    if (status) {
      sql += ' AND status = ?';
      params.push(status);
    }

    if (scriptType) {
      sql += ' AND script_type = ?';
      params.push(scriptType);
    }

    sql += ' ORDER BY first_seen DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const results = await this.query(sql, params);
    return results.rows || results;
  }

  /**
   * Get script by ID
   */
  async getScriptById(scriptId) {
    return await this.queryOne('SELECT * FROM scripts WHERE id = ?', [scriptId]);
  }

  /**
   * Get violation by ID
   */
  async getViolationById(violationId) {
    return await this.queryOne('SELECT * FROM integrity_violations WHERE id = ?', [violationId]);
  }

  /**
   * Update violation review status
   */
  async updateViolationReview(violationId, reviewData) {
    const { reviewStatus, reviewedBy, reviewNotes } = reviewData;

    const result = await this.query(
      `UPDATE integrity_violations SET
        review_status = ?,
        reviewed_by = ?,
        reviewed_at = CURRENT_TIMESTAMP,
        review_notes = ?
      WHERE id = ?`,
      [reviewStatus, reviewedBy, reviewNotes, violationId]
    );

    return result.rowCount > 0;
  }

  /**
   * Get audit log for script
   */
  async getScriptAuditLog(scriptId, limit = 50) {
    const logs = await this.query(
      'SELECT * FROM approval_audit_log WHERE script_id = ? ORDER BY performed_at DESC LIMIT ?',
      [scriptId, limit]
    );

    return logs.rows || logs;
  }

  /**
   * Clean up old records (data retention)
   */
  async cleanupOldRecords() {
    const retentionDaysViolations = 365;
    const retentionDaysAudit = 2555; // 7 years for PCI

    // Delete old violations
    const violationsDeleted = await this.query(
      `DELETE FROM integrity_violations
       WHERE detected_at < datetime('now', '-' || ? || ' days')
       AND review_status IN ('resolved', 'false_positive')`,
      [retentionDaysViolations]
    );

    // Delete old audit logs (but keep longer for compliance)
    const auditDeleted = await this.query(
      `DELETE FROM approval_audit_log
       WHERE performed_at < datetime('now', '-' || ? || ' days')`,
      [retentionDaysAudit]
    );

    console.log(`[DB Cleanup] Deleted ${violationsDeleted.rowCount} old violations, ${auditDeleted.rowCount} old audit logs`);

    return {
      violationsDeleted: violationsDeleted.rowCount,
      auditDeleted: auditDeleted.rowCount
    };
  }

  /**
   * Close database connection
   */
  async close() {
    if (!this.isConnected) {
      return;
    }

    try {
      if (this.config.type === 'sqlite') {
        this.db.close();
      } else {
        await this.db.end();
      }

      this.isConnected = false;
      console.log('[DB] Database connection closed');
    } catch (error) {
      console.error('[DB] Error closing database:', error.message);
      throw error;
    }
  }

  /**
   * Health check
   */
  async healthCheck() {
    try {
      if (this.config.type === 'sqlite') {
        this.db.prepare('SELECT 1').get();
      } else {
        await this.db.query('SELECT 1');
      }
      return { healthy: true, type: this.config.type };
    } catch (error) {
      return { healthy: false, type: this.config.type, error: error.message };
    }
  }
}

/**
 * Singleton instance
 */
let dbInstance = null;

/**
 * Get database instance
 */
function getDatabase(config) {
  if (!dbInstance) {
    dbInstance = new DatabaseManager(config);
  }
  return dbInstance;
}

module.exports = {
  DatabaseManager,
  getDatabase
};
