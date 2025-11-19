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
 * @version 2.0.0
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
    this.SQL = null;
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
   * Initialize SQLite database using sql.js
   */
  async initializeSQLite() {
    const initSqlJs = require('sql.js');

    // Initialize sql.js
    this.SQL = await initSqlJs();

    // Ensure data directory exists
    const dbDir = path.dirname(this.config.sqlitePath);
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }

    // Load existing database or create new one
    if (fs.existsSync(this.config.sqlitePath)) {
      const buffer = fs.readFileSync(this.config.sqlitePath);
      this.db = new this.SQL.Database(buffer);
      console.log(`[DB] Loaded existing SQLite database from ${this.config.sqlitePath}`);
    } else {
      this.db = new this.SQL.Database();
      console.log(`[DB] Created new SQLite database at ${this.config.sqlitePath}`);
    }

    // Enable foreign keys
    this.db.run('PRAGMA foreign_keys = ON');
  }

  /**
   * Save SQLite database to disk
   */
  saveSQLite() {
    if (this.config.type === 'sqlite' && this.db) {
      const data = this.db.export();
      fs.writeFileSync(this.config.sqlitePath, data);
    }
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
      let schema = fs.readFileSync(this.config.schemaFile, 'utf8');

      // Adapt schema for PostgreSQL if necessary
      if (this.config.type === 'postgres') {
        schema = schema.replace(/INTEGER PRIMARY KEY AUTOINCREMENT/g, 'SERIAL PRIMARY KEY');
        schema = schema.replace(/DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP/g, 'TIMESTAMP NOT NULL DEFAULT NOW()');
        schema = schema.replace(/DATETIME,/g, 'TIMESTAMP,');
        schema = schema.replace(/DATETIME\)/g, 'TIMESTAMP)');
        schema = schema.replace(/DATETIME NOT NULL/g, 'TIMESTAMP NOT NULL');
        schema = schema.replace(/DATETIME/g, 'TIMESTAMP');
        schema = schema.replace(/BOOLEAN NOT NULL DEFAULT 0/g, 'BOOLEAN NOT NULL DEFAULT FALSE');
        schema = schema.replace(/BOOLEAN NOT NULL DEFAULT 1/g, 'BOOLEAN NOT NULL DEFAULT TRUE');
        schema = schema.replace(/BOOLEAN DEFAULT 0/g, 'BOOLEAN DEFAULT FALSE');
        schema = schema.replace(/BOOLEAN DEFAULT 1/g, 'BOOLEAN DEFAULT TRUE');
        schema = schema.replace(/BOOLEAN,/g, 'BOOLEAN,');
        schema = schema.replace(/ON DELETE SET NULL/g, 'ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE'); // For foreign key constraints
        schema = schema.replace(/ON DELETE CASCADE/g, 'ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE'); // For foreign key constraints
        // Remove SQLite-specific PRAGMA statements
        schema = schema.replace(/PRAGMA foreign_keys = ON;/g, '');
        // Remove SQLite-specific AUTOINCREMENT from other places if any
        schema = schema.replace(/AUTOINCREMENT/g, '');

        // Remove SQLite-specific triggers (we'll create PostgreSQL versions separately)
        schema = this.removeSQLiteTriggers(schema);
      }

      // Execute schema
      if (this.config.type === 'sqlite') {
        this.db.exec(schema);
        this.saveSQLite();
      } else {
        // For PostgreSQL, execute statements one by one as some might be CREATE VIEW or CREATE TRIGGER
        // which cannot be in a single query with CREATE TABLE IF NOT EXISTS
        const statements = schema.split(';').filter(s => s.trim().length > 0);
        for (const stmt of statements) {
          let sql = stmt.trim();

          // Skip empty statements
          if (!sql || sql.length === 0) continue;

          if (this.config.type === 'postgres' && /^INSERT OR IGNORE INTO/i.test(sql)) {
            // Convert SQLite-style INSERT OR IGNORE into PostgreSQL ON CONFLICT DO NOTHING
            sql = sql.replace(/^INSERT OR IGNORE INTO/i, 'INSERT INTO');

            // Determine the appropriate conflict target based on table
            let conflictTarget = '';
            if (sql.includes('admin_users')) {
              conflictTarget = ' (username)';
            } else if (sql.includes('system_config')) {
              conflictTarget = ' (key)';
            }

            if (!/ON CONFLICT/.test(sql)) {
              sql = `${sql} ON CONFLICT${conflictTarget} DO NOTHING`;
            }
          }

          try {
            await this.db.query(sql);
          } catch (err) {
            // Log but continue if it's a "already exists" error
            if (err.message.includes('already exists')) {
              console.log(`[DB] Skipping: ${err.message}`);
            } else {
              throw err;
            }
          }
        }

        // Create PostgreSQL-specific triggers
        await this.createPostgreSQLTriggers();
      }

      console.log('[DB] Migrations completed');
    } catch (error) {
      console.error('[DB] Migration failed:', error.message);
      throw error;
    }
  }

  /**
   * Remove SQLite-specific triggers from schema
   * @param {string} schema - SQL schema
   * @returns {string} Schema without SQLite triggers
   */
  removeSQLiteTriggers(schema) {
    // Remove SQLite trigger blocks (CREATE TRIGGER ... END;)
    const triggerRegex = /CREATE TRIGGER[^;]*?BEGIN[\s\S]*?END;/gi;
    return schema.replace(triggerRegex, '');
  }

  /**
   * Create PostgreSQL-compatible triggers
   */
  async createPostgreSQLTriggers() {
    console.log('[DB] Creating PostgreSQL triggers...');

    // Trigger 1: Update last_seen timestamp when violation is inserted
    const updateLastSeenFunction = `
      CREATE OR REPLACE FUNCTION update_script_last_seen_func()
      RETURNS TRIGGER AS $$
      BEGIN
        UPDATE scripts
        SET last_seen = NOW()
        WHERE id = NEW.script_id;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
    `;

    const updateLastSeenTrigger = `
      DROP TRIGGER IF EXISTS update_script_last_seen ON integrity_violations;
      CREATE TRIGGER update_script_last_seen
      AFTER INSERT ON integrity_violations
      FOR EACH ROW
      EXECUTE FUNCTION update_script_last_seen_func();
    `;

    // Trigger 2: Log approval changes to audit log
    const logApprovalFunction = `
      CREATE OR REPLACE FUNCTION log_script_approval_changes_func()
      RETURNS TRIGGER AS $$
      BEGIN
        IF OLD.status IS DISTINCT FROM NEW.status THEN
          INSERT INTO approval_audit_log (
            script_id,
            action,
            previous_status,
            new_status,
            performed_by,
            notes
          ) VALUES (
            NEW.id,
            'status_changed',
            OLD.status,
            NEW.status,
            NEW.approved_by,
            NEW.approval_notes
          );
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
    `;

    const logApprovalTrigger = `
      DROP TRIGGER IF EXISTS log_script_approval_changes ON scripts;
      CREATE TRIGGER log_script_approval_changes
      AFTER UPDATE ON scripts
      FOR EACH ROW
      EXECUTE FUNCTION log_script_approval_changes_func();
    `;

    try {
      await this.db.query(updateLastSeenFunction);
      await this.db.query(updateLastSeenTrigger);
      await this.db.query(logApprovalFunction);
      await this.db.query(logApprovalTrigger);
      console.log('[DB] PostgreSQL triggers created successfully');
    } catch (err) {
      console.error('[DB] Error creating triggers:', err.message);
      // Don't throw - triggers are nice-to-have but not critical
    }
  }

  /**
   * Execute a query with parameters
   * @param {string} sql - SQL query
   * @param {Array} params - Query parameters
   * @returns {Promise<Array|Object>} Query result - Array for SELECT, Object for INSERT/UPDATE/DELETE
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
        const result = await this.queryPostgreSQL(sql, params);
        // Normalize PostgreSQL result to match SQLite format for SELECT queries
        const isSelect = sql.trim().toUpperCase().startsWith('SELECT');
        if (isSelect) {
          return result.rows || [];
        }
        return result;
      }
    } catch (error) {
      console.error('[DB Error]', error.message);
      console.error('[DB Query]', sql);
      throw error;
    }
  }

  /**
   * Execute SQLite query using sql.js
   */
  querySQLite(sql, params) {
    const isSelect = sql.trim().toUpperCase().startsWith('SELECT');
    const isInsert = sql.trim().toUpperCase().startsWith('INSERT');

    if (isSelect) {
      // Execute SELECT query
      const stmt = this.db.prepare(sql);
      stmt.bind(params);

      const rows = [];
      while (stmt.step()) {
        const row = stmt.getAsObject();
        rows.push(row);
      }
      stmt.free();

      return rows;
    } else {
      // Execute INSERT/UPDATE/DELETE using prepare/bind/step pattern
      const stmt = this.db.prepare(sql);
      stmt.bind(params);

      try {
        stmt.step();
        stmt.free();
        this.saveSQLite(); // Persist changes
      } catch (error) {
        stmt.free();
        console.error('[DB] Execute error:', error.message);
        throw error;
      }

      const result = {
        rows: [],
        rowCount: this.db.getRowsModified()
      };

      if (isInsert) {
        // For sql.js, last_insert_rowid() returns 0 after migrations create tables
        // Instead, we'll get the ID from a subsequent query in registerScript
        // This is a workaround for sql.js behavior
        result.lastInsertRowid = null;
      }

      return result;
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
      this.db.run('BEGIN TRANSACTION');
      return {
        commit: () => {
          this.db.run('COMMIT');
          this.saveSQLite();
        },
        rollback: () => {
          this.db.run('ROLLBACK');
        }
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
   * Handles inline script variations and access counting
   */
  async registerScript(scriptData) {
    const {
      url,
      contentHash,
      scriptType,
      sizeBytes,
      contentPreview,
      pageUrl,
      discoveryContext,
      scriptPosition,  // NEW: Position of inline script
      clientIp         // NEW: Client IP address
    } = scriptData;

    // Check if exact script (url + hash) already exists
    const existing = await this.queryOne(
      'SELECT id, status, access_count FROM scripts WHERE url = ? AND content_hash = ?',
      [url, contentHash]
    );

    if (existing) {
      // Script exists - update timestamps and IP (if not approved)
      const updateFields = ['last_seen = CURRENT_TIMESTAMP', 'last_accessed = CURRENT_TIMESTAMP', 'access_count = access_count + 1'];
      const updateParams = [];

      // Only update IP if script is NOT approved
      if (existing.status !== 'approved' && existing.status !== 'auto_approved' && clientIp) {
        console.log('[DB] Updating existing script with IP:', clientIp);
        updateFields.push('last_registered_ip = ?', 'last_registered_at = CURRENT_TIMESTAMP');
        updateParams.push(clientIp);
      } else if (existing.status === 'approved' || existing.status === 'auto_approved') {
        console.log('[DB] Script is approved, skipping IP update');
      } else if (!clientIp) {
        console.log('[DB] No clientIp provided, skipping IP update');
      }

      updateParams.push(existing.id);

      await this.query(
        `UPDATE scripts SET ${updateFields.join(', ')} WHERE id = ?`,
        updateParams
      );

      return {
        scriptId: existing.id,
        status: existing.status,
        isNew: false,
        isVariation: false,
        accessCount: existing.access_count + 1
      };
    }

    // For inline scripts, check if there's already a script at this position (different hash = variation)
    if (scriptType === 'inline' && scriptPosition !== null && scriptPosition !== undefined) {
      const existingAtPosition = await this.queryOne(
        `SELECT id, status, content_hash, parent_script_id, is_variation
         FROM scripts
         WHERE page_url = ? AND script_position = ? AND script_type = 'inline'
         ORDER BY first_seen ASC
         LIMIT 1`,
        [pageUrl, scriptPosition]
      );

      if (existingAtPosition && existingAtPosition.content_hash !== contentHash) {
        // This is a variation of an existing inline script
        console.log('[DB] Detected inline script variation at position', scriptPosition);

        // Determine parent script ID
        const parentScriptId = existingAtPosition.parent_script_id || existingAtPosition.id;

        // Get next variation number
        const maxVariation = await this.queryOne(
          `SELECT COALESCE(MAX(variation_number), 0) as max_var
           FROM scripts
           WHERE parent_script_id = ? OR id = ?`,
          [parentScriptId, parentScriptId]
        );
        const nextVariationNumber = (maxVariation.max_var || 0) + 1;

        // If the existing script doesn't have a parent (original script), mark it as variation #1
        if (!existingAtPosition.is_variation && !existingAtPosition.parent_script_id) {
          await this.query(
            `UPDATE scripts SET variation_number = 1 WHERE id = ?`,
            [existingAtPosition.id]
          );
        }

        // Insert variation with parent reference
        // Only include IP fields if clientIp is provided
        if (clientIp) {
          console.log('[DB] Inserting variation with IP:', clientIp);
          await this.query(
            `INSERT INTO scripts (
              url, content_hash, script_type, size_bytes, content_preview,
              page_url, discovery_context, status,
              script_position, parent_script_id, is_variation, variation_number,
              access_count, last_accessed, last_registered_ip, last_registered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_approval', ?, ?, 1, ?, 1, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP)`,
            [url, contentHash, scriptType, sizeBytes, contentPreview, pageUrl, discoveryContext,
             scriptPosition, parentScriptId, nextVariationNumber, clientIp]
          );
        } else {
          console.log('[DB] Inserting variation WITHOUT IP (clientIp is null/undefined)');
          await this.query(
            `INSERT INTO scripts (
              url, content_hash, script_type, size_bytes, content_preview,
              page_url, discovery_context, status,
              script_position, parent_script_id, is_variation, variation_number,
              access_count, last_accessed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_approval', ?, ?, 1, ?, 1, CURRENT_TIMESTAMP)`,
            [url, contentHash, scriptType, sizeBytes, contentPreview, pageUrl, discoveryContext,
             scriptPosition, parentScriptId, nextVariationNumber]
          );
        }

        // Query back the inserted record
        const inserted = await this.queryOne(
          'SELECT id, status FROM scripts WHERE url = ? AND content_hash = ?',
          [url, contentHash]
        );

        return {
          scriptId: inserted.id,
          status: inserted.status,
          isNew: true,
          isVariation: true,
          parentScriptId: parentScriptId,
          variationNumber: nextVariationNumber,
          accessCount: 1
        };
      }
    }

    // Insert new script (not a variation)
    // Only include IP fields if clientIp is provided
    if (clientIp) {
      console.log('[DB] Inserting new script with IP:', clientIp);
      await this.query(
        `INSERT INTO scripts (
          url, content_hash, script_type, size_bytes, content_preview,
          page_url, discovery_context, status,
          script_position, access_count, last_accessed, last_registered_ip, last_registered_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_approval', ?, 1, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP)`,
        [url, contentHash, scriptType, sizeBytes, contentPreview, pageUrl, discoveryContext,
         scriptType === 'inline' ? scriptPosition : null, clientIp]
      );
    } else {
      console.log('[DB] Inserting new script WITHOUT IP (clientIp is null/undefined)');
      await this.query(
        `INSERT INTO scripts (
          url, content_hash, script_type, size_bytes, content_preview,
          page_url, discovery_context, status,
          script_position, access_count, last_accessed
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_approval', ?, 1, CURRENT_TIMESTAMP)`,
        [url, contentHash, scriptType, sizeBytes, contentPreview, pageUrl, discoveryContext,
         scriptType === 'inline' ? scriptPosition : null]
      );
    }

    // Query back the inserted record to get its ID (workaround for sql.js last_insert_rowid issue)
    const inserted = await this.queryOne(
      'SELECT id, status FROM scripts WHERE url = ? AND content_hash = ?',
      [url, contentHash]
    );

    return {
      scriptId: inserted.id,
      status: inserted.status,
      isNew: true,
      isVariation: false,
      accessCount: 1
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
   * Increment access count and get script status by hash
   * This is the primary method for checking scripts on each page load.
   */
  async incrementAccessCountAndGetStatus(contentHash) {
    // First, check if the script exists to avoid updating nothing
    const existingScript = await this.getScriptStatus(contentHash);
    if (!existingScript) {
      return null; // Or handle as a "not found" case
    }

    // Now, perform the atomic update and return the updated data
    if (this.config.type === 'sqlite') {
      // For SQLite, we perform the update and then a select.
      // While not a single atomic operation in one command, it's sufficient for this context.
      await this.query(
        'UPDATE scripts SET access_count = access_count + 1, last_accessed = CURRENT_TIMESTAMP WHERE content_hash = ?',
        [contentHash]
      );
      // Fetch the updated row to get the new access_count
      return await this.queryOne(
        'SELECT id, url, status, approved_at, access_count FROM scripts WHERE content_hash = ?',
        [contentHash]
      );
    } else { // For PostgreSQL, we can use RETURNING to do this in one query
      const result = await this.query(
        `UPDATE scripts
         SET access_count = access_count + 1, last_accessed = CURRENT_TIMESTAMP
         WHERE content_hash = $1
         RETURNING id, url, status, approved_at, access_count`,
        [contentHash]
      );
      return result.rows[0];
    }
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
        approval_notes = ?,
        last_registered_ip = NULL,
        last_registered_at = NULL
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
   * Get all admin users
   */
  async getUsers() {
    const users = await this.query('SELECT id, username, email, role, is_active, created_at, last_login_at FROM admin_users');
    return users.rows || users;
  }

  /**
   * Create a new admin user
   */
  async createUser(userData) {
    const { username, email, password, role, is_active } = userData;
    const passwordHash = await require('bcrypt').hash(password, 10);
    const result = await this.query(
      'INSERT INTO admin_users (username, email, password_hash, role, is_active) VALUES (?, ?, ?, ?, ?)',
      [username, email, passwordHash, role, is_active]
    );
    const newUserId = result.lastInsertRowid || result.rows[0]?.id;
    const newUser = await this.queryOne('SELECT id, username, email, role, is_active FROM admin_users WHERE id = ?', [newUserId]);
    return newUser;
  }

  /**
   * Update an admin user
   */
  async updateUser(userId, userData) {
    const { username, email, password, role, is_active } = userData;
    const updates = [];
    const params = [];

    if (username) {
      updates.push('username = ?');
      params.push(username);
    }
    if (email) {
      updates.push('email = ?');
      params.push(email);
    }
    if (password) {
      const passwordHash = await require('bcrypt').hash(password, 10);
      updates.push('password_hash = ?');
      params.push(passwordHash);
    }
    if (role) {
      updates.push('role = ?');
      params.push(role);
    }
    if (is_active !== undefined) {
      updates.push('is_active = ?');
      params.push(is_active);
    }

    if (updates.length === 0) {
      return this.queryOne('SELECT id, username, email, role, is_active FROM admin_users WHERE id = ?', [userId]);
    }

    params.push(userId);
    const sql = `UPDATE admin_users SET ${updates.join(', ')} WHERE id = ?`;
    await this.query(sql, params);

    return this.queryOne('SELECT id, username, email, role, is_active FROM admin_users WHERE id = ?', [userId]);
  }

  /**
   * Delete an admin user
   */
  async deleteUser(userId) {
    const result = await this.query('DELETE FROM admin_users WHERE id = ?', [userId]);
    return result.rowCount > 0;
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
        this.saveSQLite();
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
        const stmt = this.db.prepare('SELECT 1');
        stmt.step();
        stmt.free();
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
