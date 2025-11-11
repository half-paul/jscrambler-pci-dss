/**
 * Database Schema for Script Integrity Monitoring System
 * PCI DSS v4.0 Requirement 6.4.3 Compliance
 *
 * This schema supports both SQLite (development) and PostgreSQL (production)
 * Auto-detection workflow with approval process
 *
 * @version 1.0.0
 */

-- ============================================================================
-- SCRIPTS INVENTORY TABLE
-- ============================================================================
-- Stores all detected scripts with approval status
CREATE TABLE IF NOT EXISTS scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Use SERIAL for PostgreSQL

    -- Script Identification
    url TEXT NOT NULL,                      -- Script URL (full URL for external, identifier for inline)
    content_hash TEXT NOT NULL,             -- SHA-384 hash of script content
    script_type TEXT NOT NULL CHECK(script_type IN ('inline', 'external')),

    -- Script Metadata
    size_bytes INTEGER,                     -- Script size in bytes
    content_preview TEXT,                   -- First 500 chars of content (for review)

    -- Discovery Information
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    page_url TEXT NOT NULL,                 -- Page where script was first discovered
    discovery_context TEXT,                 -- Additional context (loadType, iframe, etc.)

    -- Approval Status
    status TEXT NOT NULL DEFAULT 'pending_approval'
        CHECK(status IN ('pending_approval', 'approved', 'rejected', 'flagged', 'auto_approved')),

    -- Approval Metadata
    approved_by TEXT,                       -- Username or admin ID who approved/rejected
    approved_at DATETIME,                   -- When approval decision was made
    rejection_reason TEXT,                  -- Reason for rejection (if applicable)
    approval_notes TEXT,                    -- Additional notes from approver

    -- Business Justification (PCI DSS requirement)
    business_justification TEXT,            -- Required written justification
    script_purpose TEXT,                    -- What the script does
    script_owner TEXT,                      -- Who owns/maintains this script

    -- Risk Assessment
    risk_level TEXT CHECK(risk_level IN ('low', 'medium', 'high', 'critical')),
    requires_review_date DATETIME,          -- When script needs re-review

    -- Indexing for performance
    UNIQUE(url, content_hash)               -- Prevent duplicate entries
);

-- Indexes for scripts table
CREATE INDEX IF NOT EXISTS idx_scripts_status ON scripts(status);
CREATE INDEX IF NOT EXISTS idx_scripts_url ON scripts(url);
CREATE INDEX IF NOT EXISTS idx_scripts_hash ON scripts(content_hash);
CREATE INDEX IF NOT EXISTS idx_scripts_first_seen ON scripts(first_seen);
CREATE INDEX IF NOT EXISTS idx_scripts_type ON scripts(script_type);

-- ============================================================================
-- INTEGRITY VIOLATIONS TABLE
-- ============================================================================
-- Stores detected integrity violations (hash mismatches, unauthorized changes)
CREATE TABLE IF NOT EXISTS integrity_violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Use SERIAL for PostgreSQL

    -- Reference to script (if known)
    script_id INTEGER,                      -- NULL if script not in inventory yet

    -- Violation Details
    script_url TEXT NOT NULL,               -- Script URL or identifier
    old_hash TEXT,                          -- Expected hash (from baseline)
    new_hash TEXT NOT NULL,                 -- Actual hash detected
    violation_type TEXT NOT NULL CHECK(violation_type IN (
        'HASH_MISMATCH',                    -- Known script with changed content
        'NO_BASELINE_HASH',                 -- New/unknown script
        'SRI_MISMATCH',                     -- SRI attribute doesn't match
        'UNAUTHORIZED_SCRIPT',              -- Script not in approved list
        'PROCESSING_ERROR'                  -- Error during processing
    )),

    -- Detection Context
    detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    page_url TEXT NOT NULL,                 -- Page where violation occurred
    user_session TEXT,                      -- Session identifier (hashed)
    user_agent TEXT,                        -- Browser user agent
    ip_address TEXT,                        -- Client IP (hashed for privacy)

    -- Severity
    severity TEXT NOT NULL DEFAULT 'HIGH'
        CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    -- Action Taken
    action_taken TEXT CHECK(action_taken IN ('REPORTED', 'BLOCKED', 'QUEUED')),

    -- Review Status
    review_status TEXT DEFAULT 'pending'
        CHECK(review_status IN ('pending', 'investigating', 'resolved', 'false_positive', 'confirmed_attack')),
    reviewed_by TEXT,
    reviewed_at DATETIME,
    review_notes TEXT,

    -- Additional Metadata
    load_type TEXT,                         -- How script was loaded (initial-load, dynamic, etc.)
    context TEXT,                           -- Additional context (JSON format)

    FOREIGN KEY (script_id) REFERENCES scripts(id) ON DELETE SET NULL
);

-- Indexes for violations table
CREATE INDEX IF NOT EXISTS idx_violations_detected_at ON integrity_violations(detected_at);
CREATE INDEX IF NOT EXISTS idx_violations_script_id ON integrity_violations(script_id);
CREATE INDEX IF NOT EXISTS idx_violations_type ON integrity_violations(violation_type);
CREATE INDEX IF NOT EXISTS idx_violations_severity ON integrity_violations(severity);
CREATE INDEX IF NOT EXISTS idx_violations_review_status ON integrity_violations(review_status);
CREATE INDEX IF NOT EXISTS idx_violations_url ON integrity_violations(script_url);

-- ============================================================================
-- APPROVAL AUDIT LOG
-- ============================================================================
-- Maintains complete audit trail of all approval decisions
CREATE TABLE IF NOT EXISTS approval_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Use SERIAL for PostgreSQL

    script_id INTEGER NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('approved', 'rejected', 'flagged', 'unflagged', 'status_changed')),
    previous_status TEXT,
    new_status TEXT NOT NULL,

    performed_by TEXT NOT NULL,             -- Admin username or ID
    performed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason TEXT,
    notes TEXT,

    -- Request metadata
    ip_address TEXT,
    user_agent TEXT,

    FOREIGN KEY (script_id) REFERENCES scripts(id) ON DELETE CASCADE
);

-- Index for audit log
CREATE INDEX IF NOT EXISTS idx_audit_script_id ON approval_audit_log(script_id);
CREATE INDEX IF NOT EXISTS idx_audit_performed_at ON approval_audit_log(performed_at);
CREATE INDEX IF NOT EXISTS idx_audit_performed_by ON approval_audit_log(performed_by);

-- ============================================================================
-- ADMIN USERS TABLE
-- ============================================================================
-- Stores admin users authorized to approve scripts
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Use SERIAL for PostgreSQL

    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,

    -- Authentication
    password_hash TEXT NOT NULL,            -- Hashed password (bcrypt)
    api_token TEXT UNIQUE,                  -- API token for authentication
    api_token_created_at DATETIME,

    -- Role and Permissions
    role TEXT NOT NULL DEFAULT 'reviewer'
        CHECK(role IN ('viewer', 'reviewer', 'admin', 'super_admin')),

    -- Status
    is_active BOOLEAN NOT NULL DEFAULT 1,

    -- Timestamps
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME,

    -- Security
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until DATETIME
);

-- Index for admin users
CREATE INDEX IF NOT EXISTS idx_admin_username ON admin_users(username);
CREATE INDEX IF NOT EXISTS idx_admin_token ON admin_users(api_token);
CREATE INDEX IF NOT EXISTS idx_admin_email ON admin_users(email);

-- ============================================================================
-- SYSTEM CONFIGURATION TABLE
-- ============================================================================
-- Stores system-wide configuration settings
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT
);

-- Insert default configuration
INSERT OR IGNORE INTO system_config (key, value, description) VALUES
    ('auto_approval_enabled', 'false', 'Enable automatic approval for whitelisted domains'),
    ('auto_approval_domains', '[]', 'JSON array of domains for auto-approval'),
    ('hash_algorithm', 'SHA-384', 'Hash algorithm used for integrity checks'),
    ('violation_alert_email', '', 'Email address for violation alerts'),
    ('violation_alert_slack', '', 'Slack webhook URL for alerts'),
    ('approval_required_threshold', 'all', 'Require approval for: all, external_only, high_risk'),
    ('session_timeout_minutes', '30', 'Admin session timeout in minutes'),
    ('rate_limit_per_session', '100', 'Max violation reports per session per hour'),
    ('retention_days_violations', '365', 'How long to keep violation records'),
    ('retention_days_audit', '2555', 'How long to keep audit logs (7 years for PCI)');

-- ============================================================================
-- NOTIFICATION QUEUE TABLE
-- ============================================================================
-- Queue for pending notifications (email, Slack, etc.)
CREATE TABLE IF NOT EXISTS notification_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    notification_type TEXT NOT NULL CHECK(notification_type IN ('email', 'slack', 'sms', 'webhook')),
    recipient TEXT NOT NULL,                -- Email address, Slack channel, phone number

    subject TEXT,
    message TEXT NOT NULL,

    priority TEXT DEFAULT 'normal' CHECK(priority IN ('low', 'normal', 'high', 'critical')),

    -- Related entities
    script_id INTEGER,
    violation_id INTEGER,

    -- Status
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'sent', 'failed', 'cancelled')),
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at DATETIME,
    error_message TEXT,

    FOREIGN KEY (script_id) REFERENCES scripts(id) ON DELETE SET NULL,
    FOREIGN KEY (violation_id) REFERENCES integrity_violations(id) ON DELETE SET NULL
);

-- Index for notification queue
CREATE INDEX IF NOT EXISTS idx_notifications_status ON notification_queue(status);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notification_queue(created_at);
CREATE INDEX IF NOT EXISTS idx_notifications_priority ON notification_queue(priority);

-- ============================================================================
-- SCRIPT RELATIONSHIPS TABLE
-- ============================================================================
-- Track relationships between scripts (dependencies, loaded by, etc.)
CREATE TABLE IF NOT EXISTS script_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    parent_script_id INTEGER NOT NULL,      -- Script that loads another
    child_script_id INTEGER NOT NULL,       -- Script being loaded

    relationship_type TEXT NOT NULL CHECK(relationship_type IN (
        'loads',                            -- Parent loads child
        'depends_on',                       -- Parent depends on child
        'loaded_by_page',                   -- Script loaded by specific page
        'injected_by'                       -- Script injected by another
    )),

    first_observed DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_observed DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    observation_count INTEGER DEFAULT 1,

    UNIQUE(parent_script_id, child_script_id, relationship_type),
    FOREIGN KEY (parent_script_id) REFERENCES scripts(id) ON DELETE CASCADE,
    FOREIGN KEY (child_script_id) REFERENCES scripts(id) ON DELETE CASCADE
);

-- ============================================================================
-- VIEWS FOR REPORTING
-- ============================================================================

-- View: Pending Approvals
CREATE VIEW IF NOT EXISTS v_pending_approvals AS
SELECT
    s.id,
    s.url,
    s.content_hash,
    s.script_type,
    s.size_bytes,
    s.content_preview,
    s.first_seen,
    s.page_url,
    s.status,
    COUNT(DISTINCT iv.id) as violation_count
FROM scripts s
LEFT JOIN integrity_violations iv ON s.id = iv.script_id
WHERE s.status = 'pending_approval'
GROUP BY s.id
ORDER BY s.first_seen ASC;

-- View: Recent Violations
CREATE VIEW IF NOT EXISTS v_recent_violations AS
SELECT
    iv.*,
    s.url as script_url_full,
    s.status as script_status,
    s.script_type
FROM integrity_violations iv
LEFT JOIN scripts s ON iv.script_id = s.id
ORDER BY iv.detected_at DESC;

-- View: Compliance Summary
CREATE VIEW IF NOT EXISTS v_compliance_summary AS
SELECT
    COUNT(*) as total_scripts,
    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_scripts,
    SUM(CASE WHEN status = 'pending_approval' THEN 1 ELSE 0 END) as pending_scripts,
    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_scripts,
    SUM(CASE WHEN status = 'flagged' THEN 1 ELSE 0 END) as flagged_scripts,
    SUM(CASE WHEN script_type = 'inline' THEN 1 ELSE 0 END) as inline_scripts,
    SUM(CASE WHEN script_type = 'external' THEN 1 ELSE 0 END) as external_scripts
FROM scripts;

-- View: Violation Statistics
CREATE VIEW IF NOT EXISTS v_violation_statistics AS
SELECT
    COUNT(*) as total_violations,
    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
    SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
    SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low_count,
    SUM(CASE WHEN review_status = 'pending' THEN 1 ELSE 0 END) as pending_review,
    SUM(CASE WHEN review_status = 'confirmed_attack' THEN 1 ELSE 0 END) as confirmed_attacks
FROM integrity_violations;

-- ============================================================================
-- TRIGGERS (for SQLite - adapt for PostgreSQL)
-- ============================================================================

-- Update last_seen timestamp when script is detected again
CREATE TRIGGER IF NOT EXISTS update_script_last_seen
AFTER INSERT ON integrity_violations
FOR EACH ROW
BEGIN
    UPDATE scripts
    SET last_seen = CURRENT_TIMESTAMP
    WHERE id = NEW.script_id;
END;

-- Log approval changes to audit log
CREATE TRIGGER IF NOT EXISTS log_script_approval_changes
AFTER UPDATE ON scripts
FOR EACH ROW
WHEN OLD.status != NEW.status
BEGIN
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
END;

-- ============================================================================
-- SAMPLE DATA FOR TESTING (Optional - remove in production)
-- ============================================================================

-- Sample admin user (password: 'admin123' - CHANGE IN PRODUCTION!)
-- Password hash generated with bcrypt
INSERT OR IGNORE INTO admin_users (username, email, password_hash, role, api_token) VALUES
    ('admin', 'admin@example.com', '$2b$10$rBV2uMXVz7WqNqyNjHjCJeX.8pKz2QKZvH.kP9C4xD5L6JLhYv6OW', 'admin', 'demo-token-12345');

-- ============================================================================
-- POSTGRESQL SPECIFIC MODIFICATIONS
-- ============================================================================
-- When migrating to PostgreSQL, make these changes:
--
-- 1. Replace INTEGER PRIMARY KEY AUTOINCREMENT with SERIAL PRIMARY KEY
-- 2. Replace DATETIME with TIMESTAMP
-- 3. Replace BOOLEAN with BOOLEAN (already compatible)
-- 4. Replace INSERT OR IGNORE with INSERT ... ON CONFLICT DO NOTHING
-- 5. Rewrite triggers using PostgreSQL syntax (CREATE OR REPLACE FUNCTION + CREATE TRIGGER)
-- 6. Use appropriate timestamp functions (NOW() instead of CURRENT_TIMESTAMP)
--
-- Example PostgreSQL serial:
-- id SERIAL PRIMARY KEY,
--
-- Example PostgreSQL timestamp:
-- created_at TIMESTAMP NOT NULL DEFAULT NOW(),
--
-- Example PostgreSQL insert:
-- INSERT INTO system_config (key, value, description)
-- VALUES ('key', 'value', 'desc')
-- ON CONFLICT (key) DO NOTHING;
-- ============================================================================
