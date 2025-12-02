/**
 * PostgreSQL Database Schema for Script Integrity Monitoring System
 * PCI DSS v4.0 Requirement 6.4.3 Compliance
 *
 * Native PostgreSQL schema with proper data types, triggers, and constraints
 * Auto-detection workflow with approval process
 *
 * @version 1.0.0
 */

-- ============================================================================
-- SCRIPTS INVENTORY TABLE
-- ============================================================================
-- Stores all detected scripts with approval status
CREATE TABLE IF NOT EXISTS scripts (
    id SERIAL PRIMARY KEY,

    -- Script Identification
    url TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    script_type TEXT NOT NULL CHECK(script_type IN ('inline', 'external')),

    -- Script Metadata
    size_bytes INTEGER,
    content_preview TEXT,

    -- Discovery Information
    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    page_url TEXT NOT NULL,
    discovery_context TEXT,

    -- Approval Status
    status TEXT NOT NULL DEFAULT 'pending_approval'
        CHECK(status IN ('pending_approval', 'approved', 'rejected', 'flagged', 'auto_approved')),

    -- Approval Metadata
    approved_by TEXT,
    approved_at TIMESTAMP,
    rejection_reason TEXT,
    approval_notes TEXT,

    -- Business Justification (PCI DSS requirement)
    business_justification TEXT,
    script_purpose TEXT,
    script_owner TEXT,

    -- Risk Assessment
    risk_level TEXT CHECK(risk_level IN ('low', 'medium', 'high', 'critical')),
    requires_review_date TIMESTAMP,

    -- Access Tracking
    access_count INTEGER DEFAULT 0,
    last_accessed TIMESTAMP,

    -- Registration Tracking
    last_registered_ip TEXT,
    last_registered_at TIMESTAMP,

    -- Inline Script Variation Tracking
    script_position INTEGER,
    parent_script_id INTEGER,
    is_variation BOOLEAN DEFAULT FALSE,
    variation_number INTEGER,

    -- Constraints
    UNIQUE(url, content_hash),
    FOREIGN KEY (parent_script_id) REFERENCES scripts(id) ON DELETE SET NULL
);

-- Indexes for scripts table
CREATE INDEX IF NOT EXISTS idx_scripts_status ON scripts(status);
CREATE INDEX IF NOT EXISTS idx_scripts_url ON scripts(url);
CREATE INDEX IF NOT EXISTS idx_scripts_hash ON scripts(content_hash);
CREATE INDEX IF NOT EXISTS idx_scripts_first_seen ON scripts(first_seen);
CREATE INDEX IF NOT EXISTS idx_scripts_type ON scripts(script_type);
CREATE INDEX IF NOT EXISTS idx_scripts_parent ON scripts(parent_script_id);
CREATE INDEX IF NOT EXISTS idx_scripts_position ON scripts(script_position);
CREATE INDEX IF NOT EXISTS idx_scripts_access_count ON scripts(access_count);

-- ============================================================================
-- INTEGRITY VIOLATIONS TABLE
-- ============================================================================
-- Stores detected integrity violations (hash mismatches, unauthorized changes)
CREATE TABLE IF NOT EXISTS integrity_violations (
    id SERIAL PRIMARY KEY,

    -- Reference to script (if known)
    script_id INTEGER,

    -- Violation Details
    script_url TEXT NOT NULL,
    old_hash TEXT,
    new_hash TEXT NOT NULL,
    violation_type TEXT NOT NULL CHECK(violation_type IN (
        'HASH_MISMATCH',
        'NO_BASELINE_HASH',
        'SRI_MISMATCH',
        'UNAUTHORIZED_SCRIPT',
        'PROCESSING_ERROR',
        'PENDING_APPROVAL',
        'NEW_SCRIPT',
        'REJECTED_BY_ADMIN'
    )),

    -- Detection Context
    detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
    page_url TEXT NOT NULL,
    user_session TEXT,
    user_agent TEXT,
    ip_address TEXT,

    -- Severity
    severity TEXT NOT NULL DEFAULT 'HIGH'
        CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    -- Action Taken
    action_taken TEXT CHECK(action_taken IN ('REPORTED', 'BLOCKED', 'QUEUED')),

    -- Review Status
    review_status TEXT DEFAULT 'pending'
        CHECK(review_status IN ('pending', 'investigating', 'resolved', 'false_positive', 'confirmed_attack')),
    reviewed_by TEXT,
    reviewed_at TIMESTAMP,
    review_notes TEXT,

    -- Additional Metadata
    load_type TEXT,
    context TEXT,

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
    id SERIAL PRIMARY KEY,

    script_id INTEGER NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('approved', 'rejected', 'flagged', 'unflagged', 'status_changed')),
    previous_status TEXT,
    new_status TEXT NOT NULL,

    performed_by TEXT NOT NULL,
    performed_at TIMESTAMP NOT NULL DEFAULT NOW(),
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
    id SERIAL PRIMARY KEY,

    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,

    -- Authentication
    password_hash TEXT NOT NULL,
    api_token TEXT UNIQUE,
    api_token_created_at TIMESTAMP,

    -- MFA (Multi-Factor Authentication)
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret TEXT,
    mfa_backup_codes TEXT,
    mfa_setup_at TIMESTAMP,

    -- Role and Permissions
    role TEXT NOT NULL DEFAULT 'reviewer'
        CHECK(role IN ('viewer', 'reviewer', 'admin', 'super_admin')),

    -- Status
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMP,

    -- Security
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);

-- Index for admin users
CREATE INDEX IF NOT EXISTS idx_admin_username ON admin_users(username);
CREATE INDEX IF NOT EXISTS idx_admin_token ON admin_users(api_token);
CREATE INDEX IF NOT EXISTS idx_admin_email ON admin_users(email);

-- ============================================================================
-- ADMIN SESSIONS TABLE
-- ============================================================================
-- Tracks active admin sessions with JWT tokens
CREATE TABLE IF NOT EXISTS admin_sessions (
    id SERIAL PRIMARY KEY,

    admin_id INTEGER NOT NULL,
    jwt_token TEXT UNIQUE NOT NULL,
    refresh_token TEXT UNIQUE NOT NULL,

    -- Session Info
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    last_activity TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Security
    ip_address TEXT,
    user_agent TEXT,
    is_revoked BOOLEAN DEFAULT FALSE,

    FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE CASCADE
);

-- Indexes for sessions
CREATE INDEX IF NOT EXISTS idx_sessions_admin_id ON admin_sessions(admin_id);
CREATE INDEX IF NOT EXISTS idx_sessions_jwt_token ON admin_sessions(jwt_token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON admin_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_is_revoked ON admin_sessions(is_revoked);

-- ============================================================================
-- SYSTEM CONFIGURATION TABLE
-- ============================================================================
-- Stores system-wide configuration settings
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_by TEXT
);

-- Insert default configuration
INSERT INTO system_config (key, value, description)
VALUES
    ('auto_approval_enabled', 'false', 'Enable automatic approval for whitelisted domains'),
    ('auto_approval_domains', '[]', 'JSON array of domains for auto-approval'),
    ('hash_algorithm', 'SHA-384', 'Hash algorithm used for integrity checks'),
    ('violation_alert_email', '', 'Email addresses for violation alerts (comma-separated)'),
    ('violation_alert_slack', '', 'Slack webhook URL for alerts'),
    ('approval_required_threshold', 'all', 'Require approval for: all, external_only, high_risk'),
    ('session_timeout_minutes', '30', 'Admin session timeout in minutes'),
    ('rate_limit_per_session', '100', 'Max violation reports per session per hour'),
    ('retention_days_violations', '365', 'How long to keep violation records'),
    ('retention_days_audit', '2555', 'How long to keep audit logs (7 years for PCI)'),
    ('alert_batch_interval_minutes', '15', 'How often to send batched alerts (in minutes)'),
    ('alert_violations_enabled', 'false', 'Enable alerts for integrity violations'),
    ('alert_new_scripts_enabled', 'false', 'Enable alerts for new pending scripts'),
    ('alert_last_sent_violations', '', 'Timestamp of last violation alert sent (internal)'),
    ('alert_last_sent_new_scripts', '', 'Timestamp of last new script alert sent (internal)')
ON CONFLICT (key) DO NOTHING;

-- ============================================================================
-- NOTIFICATION QUEUE TABLE
-- ============================================================================
-- Queue for pending notifications (email, Slack, etc.)
CREATE TABLE IF NOT EXISTS notification_queue (
    id SERIAL PRIMARY KEY,

    notification_type TEXT NOT NULL CHECK(notification_type IN ('email', 'slack', 'sms', 'webhook')),
    recipient TEXT NOT NULL,

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

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMP,
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
    id SERIAL PRIMARY KEY,

    parent_script_id INTEGER NOT NULL,
    child_script_id INTEGER NOT NULL,

    relationship_type TEXT NOT NULL CHECK(relationship_type IN (
        'loads',
        'depends_on',
        'loaded_by_page',
        'injected_by'
    )),

    first_observed TIMESTAMP NOT NULL DEFAULT NOW(),
    last_observed TIMESTAMP NOT NULL DEFAULT NOW(),
    observation_count INTEGER DEFAULT 1,

    UNIQUE(parent_script_id, child_script_id, relationship_type),
    FOREIGN KEY (parent_script_id) REFERENCES scripts(id) ON DELETE CASCADE,
    FOREIGN KEY (child_script_id) REFERENCES scripts(id) ON DELETE CASCADE
);

-- ============================================================================
-- VIEWS FOR REPORTING
-- ============================================================================

-- View: Pending Approvals
CREATE OR REPLACE VIEW v_pending_approvals AS
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
    s.access_count,
    s.script_position,
    s.parent_script_id,
    s.is_variation,
    s.variation_number,
    COUNT(DISTINCT iv.id) as violation_count
FROM scripts s
LEFT JOIN integrity_violations iv ON s.id = iv.script_id
WHERE s.status = 'pending_approval'
GROUP BY s.id
ORDER BY s.first_seen ASC;

-- View: Recent Violations
CREATE OR REPLACE VIEW v_recent_violations AS
SELECT
    iv.*,
    s.url as script_url_full,
    s.status as script_status,
    s.script_type
FROM integrity_violations iv
LEFT JOIN scripts s ON iv.script_id = s.id
ORDER BY iv.detected_at DESC;

-- View: Compliance Summary
CREATE OR REPLACE VIEW v_compliance_summary AS
SELECT
    COUNT(*) as total_scripts,
    COALESCE(SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END), 0) as approved_scripts,
    COALESCE(SUM(CASE WHEN status = 'pending_approval' THEN 1 ELSE 0 END), 0) as pending_scripts,
    COALESCE(SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END), 0) as rejected_scripts,
    COALESCE(SUM(CASE WHEN status = 'flagged' THEN 1 ELSE 0 END), 0) as flagged_scripts,
    COALESCE(SUM(CASE WHEN script_type = 'inline' THEN 1 ELSE 0 END), 0) as inline_scripts,
    COALESCE(SUM(CASE WHEN script_type = 'external' THEN 1 ELSE 0 END), 0) as external_scripts,
    COALESCE(SUM(CASE WHEN is_variation = TRUE THEN 1 ELSE 0 END), 0) as variation_scripts,
    COALESCE(SUM(access_count), 0) as total_accesses
FROM scripts;

-- ============================================================================
-- HTTP HEADERS BASELINE TABLE (PCI DSS 11.6.1)
-- ============================================================================
-- Stores baseline HTTP headers for payment pages
CREATE TABLE IF NOT EXISTS http_headers_baseline (
    id SERIAL PRIMARY KEY,

    page_url TEXT NOT NULL UNIQUE,           -- Page URL being monitored
    headers_json TEXT NOT NULL,              -- JSON object of baseline headers

    -- Session/Client Info
    session_id TEXT,
    user_agent TEXT,

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_verified TIMESTAMP DEFAULT NOW(),

    -- Approval
    approved_by TEXT,
    approved_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_headers_baseline_page ON http_headers_baseline(page_url);
CREATE INDEX IF NOT EXISTS idx_headers_baseline_created ON http_headers_baseline(created_at);

-- ============================================================================
-- HTTP HEADER VIOLATIONS TABLE (PCI DSS 11.6.1)
-- ============================================================================
-- Stores detected header tampering violations
CREATE TABLE IF NOT EXISTS header_violations (
    id SERIAL PRIMARY KEY,

    page_url TEXT NOT NULL,
    header_name TEXT NOT NULL,
    violation_type TEXT NOT NULL CHECK(violation_type IN (
        'HEADER_REMOVED',                    -- Critical header was removed
        'HEADER_MODIFIED',                   -- Header value changed
        'HEADER_MISSING'                     -- Expected header never present
    )),

    expected_value TEXT,                     -- Value from baseline
    actual_value TEXT,                       -- Current value (null if removed)

    severity TEXT DEFAULT 'HIGH' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    -- Session Info
    session_id TEXT,
    user_agent TEXT,
    ip_address TEXT,

    -- Timestamps
    detected_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Review Status
    review_status TEXT DEFAULT 'pending' CHECK(review_status IN ('pending', 'investigating', 'resolved', 'false_positive', 'confirmed_attack')),
    reviewed_by TEXT,
    reviewed_at TIMESTAMP,
    review_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_header_violations_page ON header_violations(page_url);
CREATE INDEX IF NOT EXISTS idx_header_violations_detected ON header_violations(detected_at);
CREATE INDEX IF NOT EXISTS idx_header_violations_status ON header_violations(review_status);
CREATE INDEX IF NOT EXISTS idx_header_violations_type ON header_violations(violation_type);
CREATE INDEX IF NOT EXISTS idx_header_violations_severity ON header_violations(severity);

-- ============================================================================
-- NETWORK VIOLATIONS TABLE (PCI DSS 11.6.1)
-- ============================================================================
-- Stores unauthorized network request attempts
CREATE TABLE IF NOT EXISTS network_violations (
    id SERIAL PRIMARY KEY,

    page_url TEXT NOT NULL,                  -- Source page
    request_type TEXT NOT NULL CHECK(request_type IN ('fetch', 'xhr', 'beacon', 'form')),
    destination_url TEXT NOT NULL,           -- Where data was being sent
    destination_origin TEXT,                 -- Origin domain

    severity TEXT DEFAULT 'CRITICAL' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    blocked BOOLEAN DEFAULT FALSE,           -- Whether request was blocked

    -- Session Info
    session_id TEXT,
    user_agent TEXT,
    ip_address TEXT,

    -- Timestamps
    detected_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Review Status
    review_status TEXT DEFAULT 'pending' CHECK(review_status IN ('pending', 'investigating', 'resolved', 'false_positive', 'confirmed_attack', 'whitelisted')),
    reviewed_by TEXT,
    reviewed_at TIMESTAMP,
    review_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_network_violations_page ON network_violations(page_url);
CREATE INDEX IF NOT EXISTS idx_network_violations_detected ON network_violations(detected_at);
CREATE INDEX IF NOT EXISTS idx_network_violations_blocked ON network_violations(blocked);
CREATE INDEX IF NOT EXISTS idx_network_violations_status ON network_violations(review_status);
CREATE INDEX IF NOT EXISTS idx_network_violations_type ON network_violations(request_type);
CREATE INDEX IF NOT EXISTS idx_network_violations_destination ON network_violations(destination_origin);

-- ============================================================================
-- NETWORK WHITELIST TABLE (PCI DSS 11.6.1)
-- ============================================================================
-- Stores whitelisted network destinations
CREATE TABLE IF NOT EXISTS network_whitelist (
    id SERIAL PRIMARY KEY,

    domain TEXT NOT NULL UNIQUE,             -- Domain or origin to whitelist
    pattern_type TEXT DEFAULT 'exact' CHECK(pattern_type IN ('exact', 'regex', 'subdomain')),

    -- Approval Info
    business_justification TEXT,
    added_by TEXT NOT NULL,
    added_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP                     -- Optional expiration
);

CREATE INDEX IF NOT EXISTS idx_network_whitelist_domain ON network_whitelist(domain);
CREATE INDEX IF NOT EXISTS idx_network_whitelist_active ON network_whitelist(is_active);

-- View: Violation Statistics
CREATE OR REPLACE VIEW v_violation_statistics AS
SELECT
    COUNT(*) as total_violations,
    COALESCE(SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) as critical_count,
    COALESCE(SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0) as high_count,
    COALESCE(SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END), 0) as medium_count,
    COALESCE(SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END), 0) as low_count,
    COALESCE(SUM(CASE WHEN review_status = 'pending' THEN 1 ELSE 0 END), 0) as pending_review,
    COALESCE(SUM(CASE WHEN review_status = 'confirmed_attack' THEN 1 ELSE 0 END), 0) as confirmed_attacks
FROM integrity_violations;

-- View: Header Violations Summary (PCI DSS 11.6.1)
CREATE OR REPLACE VIEW v_header_violations_summary AS
SELECT
    page_url,
    COUNT(*) as violation_count,
    MAX(detected_at) as last_violation,
    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
    SUM(CASE WHEN review_status = 'pending' THEN 1 ELSE 0 END) as pending_review
FROM header_violations
GROUP BY page_url
ORDER BY last_violation DESC;

-- View: Network Violations Summary (PCI DSS 11.6.1)
CREATE OR REPLACE VIEW v_network_violations_summary AS
SELECT
    destination_origin,
    COUNT(*) as violation_count,
    SUM(CASE WHEN blocked = TRUE THEN 1 ELSE 0 END) as blocked_count,
    MAX(detected_at) as last_violation,
    SUM(CASE WHEN review_status = 'pending' THEN 1 ELSE 0 END) as pending_review
FROM network_violations
GROUP BY destination_origin
ORDER BY violation_count DESC;

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Trigger 1: Update last_seen timestamp when violation is inserted
CREATE OR REPLACE FUNCTION update_script_last_seen_func()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE scripts
    SET last_seen = NOW()
    WHERE id = NEW.script_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_script_last_seen ON integrity_violations;
CREATE TRIGGER update_script_last_seen
AFTER INSERT ON integrity_violations
FOR EACH ROW
EXECUTE FUNCTION update_script_last_seen_func();

-- Trigger 2: Log approval changes to audit log
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

DROP TRIGGER IF EXISTS log_script_approval_changes ON scripts;
CREATE TRIGGER log_script_approval_changes
AFTER UPDATE ON scripts
FOR EACH ROW
EXECUTE FUNCTION log_script_approval_changes_func();

-- ============================================================================
-- SAMPLE DATA FOR TESTING (Optional - remove in production)
-- ============================================================================

-- Sample admin user (password: 'admin123' - CHANGE IN PRODUCTION!)
-- Password hash generated with bcrypt
INSERT INTO admin_users (username, email, password_hash, role, api_token) VALUES
    ('admin', 'admin@example.com', '$2b$10$YV65lKzIz/IUvZmpKB9IWeBG3j/Tz3Wg022hoSyN7cKXEMreEQBlW', 'admin', 'demo-token-12345')
ON CONFLICT (username) DO NOTHING;

-- ============================================================================
-- AUDIT TRAIL TABLE (PostgreSQL)
-- ============================================================================
-- Comprehensive audit logging for all admin actions
-- PCI DSS requirement for audit trail with 7-year retention
CREATE TABLE IF NOT EXISTS audit_trail (
    id SERIAL PRIMARY KEY,

    -- Timestamp (indexed for fast queries)
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),

    -- User Information
    user_id INTEGER,                        -- References admin_users(id)
    username TEXT NOT NULL,                 -- Username for quick access
    user_role TEXT,                         -- Role at time of action

    -- Action Information
    action_type TEXT NOT NULL CHECK(action_type IN (
        -- Script Management
        'script_approved', 'script_rejected', 'script_deleted', 'scripts_bulk_deleted',
        -- Violation Management
        'violation_reviewed', 'violation_deleted', 'violations_bulk_deleted',
        -- Header Management
        'header_violation_reviewed', 'header_violation_deleted', 'header_violations_bulk_deleted',
        'header_baseline_deleted', 'header_baselines_bulk_deleted',
        -- Network Management
        'network_violation_reviewed', 'network_violation_deleted', 'network_violations_bulk_deleted',
        'domain_whitelisted', 'domain_removed_from_whitelist',
        -- User Management
        'user_created', 'user_updated', 'user_deleted', 'user_password_changed',
        'user_role_changed', 'user_mfa_enabled', 'user_mfa_disabled',
        -- Authentication
        'login_success', 'login_failed', 'logout', 'password_reset',
        -- Settings
        'settings_updated', 'config_changed'
    )),

    -- Entity Information (what was acted upon)
    entity_type TEXT CHECK(entity_type IN (
        'script', 'violation', 'header_violation', 'header_baseline',
        'network_violation', 'network_whitelist', 'user', 'settings', 'auth'
    )),
    entity_id TEXT,                         -- ID of the entity (can be comma-separated for bulk)
    entity_count INTEGER DEFAULT 1,         -- Number of entities affected (for bulk operations)

    -- Action Details
    action_description TEXT NOT NULL,       -- Human-readable description
    action_reason TEXT,                     -- Reason provided by user (e.g., rejection reason)

    -- Request Metadata
    ip_address TEXT,                        -- Hashed IP address
    user_agent TEXT,                        -- Browser/client info
    request_method TEXT,                    -- HTTP method (GET, POST, DELETE, etc.)
    request_path TEXT,                      -- API endpoint called

    -- Changes (for update operations)
    old_values TEXT,                        -- JSON of old values (for auditing changes)
    new_values TEXT,                        -- JSON of new values

    -- Result
    success BOOLEAN DEFAULT TRUE,           -- Whether action succeeded
    error_message TEXT,                     -- Error message if failed

    -- Compliance
    retention_until TIMESTAMP,              -- When this log can be deleted (7 years for PCI DSS)
    archived BOOLEAN DEFAULT FALSE          -- Whether archived to cold storage
);

-- Indexes for fast audit trail queries
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_trail(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_trail(username);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_trail(action_type);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_trail(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_retention ON audit_trail(retention_until);

-- View for recent audit trail (last 30 days)
CREATE OR REPLACE VIEW v_audit_trail_recent AS
SELECT
    id,
    timestamp,
    username,
    user_role,
    action_type,
    entity_type,
    entity_id,
    entity_count,
    action_description,
    action_reason,
    success,
    error_message
FROM audit_trail
WHERE timestamp >= NOW() - INTERVAL '30 days'
ORDER BY timestamp DESC;

-- View for failed actions (security monitoring)
CREATE OR REPLACE VIEW v_audit_trail_failures AS
SELECT
    id,
    timestamp,
    username,
    ip_address,
    action_type,
    action_description,
    error_message
FROM audit_trail
WHERE success = FALSE
ORDER BY timestamp DESC;
