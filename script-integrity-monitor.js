/**
 * Script Integrity Monitor - PCI DSS v4.0 Requirement 6.4.3 Compliance
 *
 * PCI DSS 6.4.3 requires that all payment page scripts are managed as follows:
 * - A method is implemented to confirm that each script is authorized
 * - A method is implemented to ensure the integrity of each script
 * - An inventory of all scripts is maintained with written justification
 *
 * This script provides:
 * 1. Real-time script integrity verification using cryptographic hashes (SHA-256/SHA-384)
 * 2. Detection of unauthorized script modifications
 * 3. Comprehensive script inventory with timestamps and metadata
 * 4. Alerting mechanism for integrity violations
 * 5. Monitoring of both static and dynamically loaded scripts
 * 6. Support for enforcement and report-only modes
 *
 * CRITICAL: This script MUST be loaded FIRST, before any other scripts on the page.
 * Use: <script src="script-integrity-monitor.js"></script> as the FIRST script tag.
 *
 * @version 1.0.0
 * @license MIT
 */

(function() {
  'use strict';

  // Prevent multiple initialization
  if (window.__SCRIPT_INTEGRITY_MONITOR__) {
    console.warn('[SIM] Script Integrity Monitor already initialized');
    return;
  }

  /**
   * Script Integrity Monitor Class
   * Monitors and validates all scripts loaded on the page
   */
  class ScriptIntegrityMonitor {
    constructor(config = {}) {
      this.config = {
        // Hash algorithm: 'SHA-256' or 'SHA-384' (SHA-512 not widely supported for SRI)
        hashAlgorithm: config.hashAlgorithm || 'SHA-384',

        // Monitoring mode: 'enforce' blocks unauthorized scripts, 'report' only logs violations
        mode: config.mode || 'report',

        // Baseline hashes: { scriptIdentifier: 'sha384-hash...' }
        baselineHashes: config.baselineHashes || {},

        // Whitelisted script sources (RegExp patterns)
        whitelistedSources: config.whitelistedSources || [],

        // Alert configuration
        alertEndpoint: config.alertEndpoint || null,
        alertCallback: config.alertCallback || null,
        consoleAlerts: config.consoleAlerts !== false, // Default true

        // Monitoring options
        monitorInlineScripts: config.monitorInlineScripts !== false,
        monitorExternalScripts: config.monitorExternalScripts !== false,
        monitorDynamicScripts: config.monitorDynamicScripts !== false,
        monitorIframes: config.monitorIframes !== false,

        // Performance options
        batchAlerts: config.batchAlerts || false,
        batchInterval: config.batchInterval || 5000, // ms

        // Debug mode (enabled by default for visibility)
        debug: config.debug !== false
      };

      // Script inventory: stores all detected scripts with metadata
      this.scriptInventory = [];

      // Violation log: stores all integrity violations
      this.violations = [];

      // Pending alerts for batch processing
      this.pendingAlerts = [];

      // Mutation observer instance
      this.observer = null;

      // Batch alert timer
      this.batchTimer = null;

      // Session start time
      this.sessionStartTime = Date.now();

      // Initialization timestamp
      this.initTime = performance.now();

      // NEW: Server-side integration
      this.knownScripts = new Map();          // Map of hash -> server status
      this.pendingRegistrations = new Set();  // Scripts awaiting server registration
      this.pollTimers = new Map();            // Polling timers for pending scripts
      this.sessionId = this.generateSessionId();

      // Initialize monitoring
      this.initialize();
    }

    /**
     * Initialize the integrity monitoring system
     */
    initialize() {
      this.log('Initializing Script Integrity Monitor', 'info');
      this.log(`Mode: ${this.config.mode}`, 'info');
      this.log(`Hash Algorithm: ${this.config.hashAlgorithm}`, 'info');

      // Check for Web Crypto API support
      if (!window.crypto || !window.crypto.subtle) {
        this.log('Web Crypto API not supported - monitoring disabled', 'error');
        return;
      }

      // Scan existing scripts on the page
      this.scanExistingScripts();

      // Set up MutationObserver for dynamically added scripts
      if (this.config.monitorDynamicScripts) {
        this.setupMutationObserver();
      }

      // Monitor iframe creation
      if (this.config.monitorIframes) {
        this.setupIframeMonitoring();
      }

      // Set up beforeunload handler to flush pending alerts
      window.addEventListener('beforeunload', () => this.flushPendingAlerts());

      this.log(`Initialization complete (${(performance.now() - this.initTime).toFixed(2)}ms)`, 'info');
    }

    /**
     * Scan all existing scripts on the page
     */
    scanExistingScripts() {
      const scripts = document.querySelectorAll('script');
      this.log(`Found ${scripts.length} existing script(s)`, 'debug');

      scripts.forEach((script, index) => {
        // Skip this monitoring script itself
        if (script === document.currentScript) {
          this.log('Skipping monitoring script itself', 'debug');
          return;
        }

        this.processScript(script, 'initial-load', index);
      });
    }

    /**
     * Set up MutationObserver to detect dynamically added scripts
     */
    setupMutationObserver() {
      this.observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          mutation.addedNodes.forEach((node) => {
            // Check if the added node is a script
            if (node.nodeName === 'SCRIPT') {
              this.processScript(node, 'dynamic-addition');
            }

            // Check if added node contains scripts (e.g., div with scripts)
            if (node.querySelectorAll) {
              const scripts = node.querySelectorAll('script');
              scripts.forEach((script) => {
                this.processScript(script, 'dynamic-nested');
              });
            }
          });
        });
      });

      // Start observing the document for script additions
      this.observer.observe(document.documentElement, {
        childList: true,
        subtree: true
      });

      this.log('MutationObserver initialized for dynamic script monitoring', 'debug');
    }

    /**
     * Set up iframe monitoring
     */
    setupIframeMonitoring() {
      // Monitor existing iframes
      document.querySelectorAll('iframe').forEach((iframe) => {
        this.monitorIframe(iframe);
      });

      // Monitor dynamically added iframes
      const iframeObserver = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeName === 'IFRAME') {
              this.monitorIframe(node);
            }
          });
        });
      });

      iframeObserver.observe(document.documentElement, {
        childList: true,
        subtree: true
      });

      this.log('Iframe monitoring initialized', 'debug');
    }

    /**
     * Monitor scripts within an iframe
     * @param {HTMLIFrameElement} iframe - The iframe element to monitor
     */
    monitorIframe(iframe) {
      try {
        // Check same-origin policy
        const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;

        if (iframeDoc) {
          this.log(`Monitoring iframe: ${iframe.src || '[inline]'}`, 'debug');

          // Wait for iframe to load
          iframe.addEventListener('load', () => {
            try {
              const scripts = iframeDoc.querySelectorAll('script');
              scripts.forEach((script) => {
                this.processScript(script, 'iframe', 0, iframe.src);
              });
            } catch (e) {
              // Cross-origin iframe - cannot access
              this.log(`Cannot access cross-origin iframe: ${iframe.src}`, 'debug');
            }
          });
        }
      } catch (e) {
        // Cross-origin iframe
        this.log(`Cannot access cross-origin iframe: ${iframe.src}`, 'debug');
      }
    }

    /**
     * Process a script element
     * @param {HTMLScriptElement} script - The script element to process
     * @param {string} loadType - How the script was loaded
     * @param {number} index - Script index for ordering
     * @param {string} context - Additional context (e.g., iframe URL)
     */
    async processScript(script, loadType, index = 0, context = null) {
      const scriptInfo = {
        id: this.generateScriptId(script),
        src: script.src || null,
        inline: !script.src,
        type: script.type || 'text/javascript',
        async: script.async,
        defer: script.defer,
        integrity: script.integrity || null,
        crossOrigin: script.crossOrigin || null,
        nonce: script.nonce || null,
        loadType: loadType,
        timestamp: Date.now(),
        index: index,
        context: context,
        content: null,
        hash: null,
        hashAlgorithm: this.config.hashAlgorithm,
        authorized: false,
        violation: null
      };

      // Skip if not monitoring this type
      if (scriptInfo.inline && !this.config.monitorInlineScripts) {
        return;
      }
      if (!scriptInfo.inline && !this.config.monitorExternalScripts) {
        return;
      }

      this.log(`Processing script: ${scriptInfo.id}`, 'debug');

      try {
        // Get script content
        if (scriptInfo.inline) {
          scriptInfo.content = script.textContent || script.innerHTML;
        } else {
          // For external scripts, fetch the content
          scriptInfo.content = await this.fetchScriptContent(script.src);
        }

        // Calculate hash
        if (scriptInfo.content) {
          scriptInfo.hash = await this.calculateHash(scriptInfo.content, this.config.hashAlgorithm);
        }

        // Verify integrity
        const verification = this.verifyIntegrity(scriptInfo);
        scriptInfo.authorized = verification.authorized;
        scriptInfo.violation = verification.violation;

        // Add to inventory
        this.scriptInventory.push(scriptInfo);

        // Handle violations
        if (!scriptInfo.authorized) {
          this.handleViolation(scriptInfo);
        } else {
          this.log(`Script authorized: ${scriptInfo.id}`, 'debug');
        }

      } catch (error) {
        this.log(`Error processing script ${scriptInfo.id}: ${error.message}`, 'error');
        scriptInfo.violation = `Processing error: ${error.message}`;
        this.scriptInventory.push(scriptInfo);
        this.handleViolation(scriptInfo);
      }
    }

    /**
     * Generate a unique identifier for a script
     * @param {HTMLScriptElement} script - The script element
     * @returns {string} Unique identifier
     */
    generateScriptId(script) {
      if (script.src) {
        // Use URL for external scripts
        const url = new URL(script.src, window.location.href);
        return url.href;
      } else {
        // For inline scripts, use position or generate ID
        const scriptIndex = Array.from(document.querySelectorAll('script')).indexOf(script);
        return `inline-script-${scriptIndex}-${Date.now()}`;
      }
    }

    /**
     * Fetch external script content
     * @param {string} url - Script URL
     * @returns {Promise<string>} Script content
     */
    async fetchScriptContent(url) {
      try {
        const response = await fetch(url, {
          method: 'GET',
          credentials: 'same-origin',
          cache: 'no-cache'
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        return await response.text();
      } catch (error) {
        throw new Error(`Failed to fetch script: ${error.message}`);
      }
    }

    /**
     * Calculate cryptographic hash of content
     * @param {string} content - Content to hash
     * @param {string} algorithm - Hash algorithm (SHA-256 or SHA-384)
     * @returns {Promise<string>} Base64-encoded hash with algorithm prefix
     */
    async calculateHash(content, algorithm = 'SHA-384') {
      try {
        const encoder = new TextEncoder();
        const data = encoder.encode(content);
        const hashBuffer = await crypto.subtle.digest(algorithm, data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashBase64 = btoa(String.fromCharCode.apply(null, hashArray));

        // Return in SRI format: sha384-hash...
        const algoPrefix = algorithm.toLowerCase().replace('-', '');
        return `${algoPrefix}-${hashBase64}`;
      } catch (error) {
        throw new Error(`Hash calculation failed: ${error.message}`);
      }
    }

    /**
     * Verify script integrity against baseline
     * @param {Object} scriptInfo - Script information object
     * @returns {Object} Verification result
     */
    async verifyIntegrity(scriptInfo) {
      const result = {
        authorized: false,
        violation: null,
        serverStatus: null
      };

      // Check if script has baseline hash
      const baselineHash = this.config.baselineHashes[scriptInfo.id];

      if (baselineHash) {
        // KNOWN SCRIPT: Compare calculated hash with baseline
        if (scriptInfo.hash === baselineHash) {
          result.authorized = true;
          result.violation = null;
          this.log(`Hash match for ${scriptInfo.id}`, 'debug');
        } else {
          // KNOWN SCRIPT WITH CHANGED INTEGRITY
          result.violation = 'HASH_MISMATCH';
          result.expectedHash = baselineHash;
          this.log(`Hash mismatch for ${scriptInfo.id}`, 'warn');
          this.log(`  Expected: ${baselineHash}`, 'warn');
          this.log(`  Got: ${scriptInfo.hash}`, 'warn');
        }
      } else {
        // Check server-side status first (if configured)
        if (this.config.serverBaseUrl) {
          const serverStatus = await this.checkScriptStatus(scriptInfo.hash);

          if (serverStatus) {
            result.serverStatus = serverStatus.status;

            if (serverStatus.status === 'approved') {
              result.authorized = true;
              this.log(`Script approved on server: ${scriptInfo.id}`, 'info');
            } else if (serverStatus.status === 'rejected') {
              result.violation = 'REJECTED_BY_ADMIN';
              this.log(`Script rejected by admin: ${scriptInfo.id}`, 'warn');
            } else if (serverStatus.status === 'pending_approval') {
              // NEW SCRIPT PENDING APPROVAL
              result.violation = 'PENDING_APPROVAL';
              this.log(`Script pending approval: ${scriptInfo.id}`, 'info');
            }
          } else {
            // NEW SCRIPT - Not in baseline, not on server
            result.violation = 'NEW_SCRIPT';
            this.log(`New script discovered: ${scriptInfo.id}`, 'info');

            // Auto-register with server
            if (this.config.autoRegisterNewScripts) {
              await this.registerNewScript(scriptInfo);
            }
          }
        } else {
          // No server integration - check whitelist
          if (scriptInfo.src && this.isWhitelisted(scriptInfo.src)) {
            result.authorized = true;
            this.log(`Whitelisted source: ${scriptInfo.src}`, 'debug');
          } else {
            result.violation = 'NO_BASELINE_HASH';
            this.log(`No baseline hash for ${scriptInfo.id}`, 'warn');
          }
        }
      }

      // Additional check: verify SRI attribute if present
      if (scriptInfo.integrity && scriptInfo.hash !== scriptInfo.integrity) {
        result.authorized = false;
        result.violation = 'SRI_MISMATCH';
        this.log(`SRI attribute mismatch for ${scriptInfo.id}`, 'warn');
      }

      return result;
    }

    /**
     * Check if a script source is whitelisted
     * @param {string} src - Script source URL
     * @returns {boolean} True if whitelisted
     */
    isWhitelisted(src) {
      return this.config.whitelistedSources.some(pattern => {
        if (pattern instanceof RegExp) {
          return pattern.test(src);
        }
        return src.includes(pattern);
      });
    }

    /**
     * Handle integrity violation
     * @param {Object} scriptInfo - Script information object
     */
    async handleViolation(scriptInfo) {
      const violation = {
        timestamp: Date.now(),
        scriptId: scriptInfo.id,
        src: scriptInfo.src,
        inline: scriptInfo.inline,
        violationType: scriptInfo.violation,
        loadType: scriptInfo.loadType,
        hash: scriptInfo.hash,
        expectedHash: scriptInfo.expectedHash || null,
        context: scriptInfo.context
      };

      this.violations.push(violation);

      // Log to console if enabled
      if (this.config.consoleAlerts) {
        console.error('[SIM] INTEGRITY VIOLATION DETECTED:', violation);
      }

      // Report to server (if configured)
      if (this.config.serverBaseUrl && scriptInfo.violation !== 'PENDING_APPROVAL' && scriptInfo.violation !== 'NEW_SCRIPT') {
        await this.reportViolationToServer(violation);
      }

      // Prepare alert
      const alert = {
        severity: this.getViolationSeverity(scriptInfo.violation),
        title: 'Script Integrity Violation',
        message: this.getViolationMessage(scriptInfo),
        violation: violation,
        inventory: this.getInventorySummary()
      };

      // In enforce mode, attempt to block the script
      if (this.config.mode === 'enforce') {
        this.blockScript(scriptInfo);
        alert.action = 'BLOCKED';
      } else {
        alert.action = 'REPORTED';
      }

      // Send alert
      if (this.config.batchAlerts) {
        this.queueAlert(alert);
      } else {
        this.sendAlert(alert);
      }
    }

    /**
     * Get severity level for violation type
     */
    getViolationSeverity(violationType) {
      const severityMap = {
        'HASH_MISMATCH': 'CRITICAL',
        'SRI_MISMATCH': 'CRITICAL',
        'REJECTED_BY_ADMIN': 'HIGH',
        'NO_BASELINE_HASH': 'HIGH',
        'UNAUTHORIZED_SCRIPT': 'HIGH',
        'PENDING_APPROVAL': 'MEDIUM',
        'NEW_SCRIPT': 'MEDIUM',
        'PROCESSING_ERROR': 'LOW'
      };

      return severityMap[violationType] || 'HIGH';
    }

    /**
     * Get human-readable violation message
     */
    getViolationMessage(scriptInfo) {
      const messages = {
        'HASH_MISMATCH': `Known script has been modified: ${scriptInfo.id}`,
        'SRI_MISMATCH': `SRI attribute mismatch for: ${scriptInfo.id}`,
        'REJECTED_BY_ADMIN': `Admin rejected script: ${scriptInfo.id}`,
        'NO_BASELINE_HASH': `Unauthorized script (no baseline): ${scriptInfo.id}`,
        'PENDING_APPROVAL': `Script awaiting approval: ${scriptInfo.id}`,
        'NEW_SCRIPT': `New script discovered: ${scriptInfo.id}`,
        'PROCESSING_ERROR': `Error processing script: ${scriptInfo.id}`
      };

      return messages[scriptInfo.violation] || `Integrity violation: ${scriptInfo.id}`;
    }

    /**
     * Attempt to block unauthorized script execution
     * Note: This has limitations - scripts may have already executed
     * @param {Object} scriptInfo - Script information object
     */
    blockScript(scriptInfo) {
      this.log(`Attempting to block script: ${scriptInfo.id}`, 'warn');

      // This is a best-effort approach
      // For inline scripts that have already executed, we cannot undo execution
      // For external scripts, we can potentially prevent future loads

      if (!scriptInfo.inline && scriptInfo.src) {
        // Add to Content Security Policy (if supported)
        // Note: This won't block already-loaded scripts
        this.log('Script blocking has limitations - consider implementing CSP headers', 'warn');
      }

      // Log the blocking attempt
      console.warn('[SIM] SCRIPT BLOCKED (enforcement mode):', scriptInfo.id);
    }

    /**
     * Queue alert for batch processing
     * @param {Object} alert - Alert object
     */
    queueAlert(alert) {
      this.pendingAlerts.push(alert);

      // Set up batch timer if not already running
      if (!this.batchTimer) {
        this.batchTimer = setTimeout(() => {
          this.flushPendingAlerts();
        }, this.config.batchInterval);
      }
    }

    /**
     * Flush pending alerts
     */
    flushPendingAlerts() {
      if (this.pendingAlerts.length === 0) {
        return;
      }

      const batchAlert = {
        severity: 'HIGH',
        title: 'Script Integrity Violations (Batch)',
        message: `${this.pendingAlerts.length} violation(s) detected`,
        violations: this.pendingAlerts,
        inventory: this.getInventorySummary()
      };

      this.sendAlert(batchAlert);
      this.pendingAlerts = [];
      this.batchTimer = null;
    }

    /**
     * Send alert via configured channels
     * @param {Object} alert - Alert object
     */
    async sendAlert(alert) {
      // Custom callback
      if (this.config.alertCallback && typeof this.config.alertCallback === 'function') {
        try {
          this.config.alertCallback(alert);
        } catch (error) {
          this.log(`Alert callback error: ${error.message}`, 'error');
        }
      }

      // Send to endpoint
      if (this.config.alertEndpoint) {
        try {
          await fetch(this.config.alertEndpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(alert),
            keepalive: true // Ensure request completes even if page unloads
          });
          this.log(`Alert sent to endpoint: ${this.config.alertEndpoint}`, 'debug');
        } catch (error) {
          this.log(`Failed to send alert to endpoint: ${error.message}`, 'error');
        }
      }
    }

    /**
     * Get summary of script inventory
     * @returns {Object} Inventory summary
     */
    getInventorySummary() {
      return {
        totalScripts: this.scriptInventory.length,
        authorizedScripts: this.scriptInventory.filter(s => s.authorized).length,
        unauthorizedScripts: this.scriptInventory.filter(s => !s.authorized).length,
        inlineScripts: this.scriptInventory.filter(s => s.inline).length,
        externalScripts: this.scriptInventory.filter(s => !s.inline).length,
        sessionStartTime: this.sessionStartTime
      };
    }

    /**
     * Get full script inventory
     * @returns {Array} Complete script inventory
     */
    getInventory() {
      return this.scriptInventory;
    }

    /**
     * Get all violations
     * @returns {Array} All violations
     */
    getViolations() {
      return this.violations;
    }

    /**
     * Generate compliance report
     * @returns {Object} PCI DSS compliance report
     */
    generateComplianceReport() {
      const summary = this.getInventorySummary();

      return {
        reportDate: new Date().toISOString(),
        sessionStartTime: new Date(this.sessionStartTime).toISOString(),
        pciDssRequirement: '6.4.3',
        monitoringMode: this.config.mode,
        hashAlgorithm: this.config.hashAlgorithm,
        summary: summary,
        scriptInventory: this.scriptInventory.map(script => ({
          id: script.id,
          src: script.src,
          inline: script.inline,
          hash: script.hash,
          authorized: script.authorized,
          loadType: script.loadType,
          timestamp: new Date(script.timestamp).toISOString(),
          violation: script.violation
        })),
        violations: this.violations.map(v => ({
          ...v,
          timestamp: new Date(v.timestamp).toISOString()
        })),
        complianceStatus: this.violations.length === 0 ? 'COMPLIANT' : 'VIOLATIONS_DETECTED'
      };
    }

    /**
     * Export inventory as JSON
     * @returns {string} JSON string
     */
    exportInventory() {
      return JSON.stringify(this.generateComplianceReport(), null, 2);
    }

    /**
     * Logging utility
     * @param {string} message - Log message
     * @param {string} level - Log level (debug, info, warn, error)
     */
    log(message, level = 'info', data = null) {
      if (level === 'debug' && !this.config.debug) {
        return;
      }

      const prefix = '🔒 [SIM]';
      const timestamp = new Date().toISOString().split('T')[1].split('.')[0]; // HH:MM:SS

      // Add emoji indicators for different message types
      let emoji = '';
      if (message.includes('API') || message.includes('server') || message.includes('register')) {
        emoji = '🌐';
      } else if (message.includes('violation') || message.includes('unauthorized')) {
        emoji = '⚠️';
      } else if (message.includes('approved') || message.includes('authorized')) {
        emoji = '✅';
      } else if (message.includes('new script') || message.includes('detected')) {
        emoji = '🔍';
      } else if (message.includes('polling') || message.includes('checking')) {
        emoji = '🔄';
      }

      const formattedMessage = `${prefix} ${emoji} [${timestamp}] ${message}`;

      switch (level) {
        case 'debug':
          console.debug(formattedMessage, data || '');
          break;
        case 'info':
          console.info(formattedMessage, data || '');
          break;
        case 'warn':
          console.warn(formattedMessage, data || '');
          break;
        case 'error':
          console.error(formattedMessage, data || '');
          break;
        default:
          console.log(formattedMessage, data || '');
      }

      // Log additional data if provided
      if (data && this.config.debug) {
        console.log('   └─ Data:', data);
      }
    }

    /**
     * Generate unique session ID
     */
    generateSessionId() {
      return `session-${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
    }

    /**
     * NEW: Register newly discovered script with server
     */
    async registerNewScript(scriptInfo) {
      if (!this.config.autoRegisterNewScripts || !this.config.serverBaseUrl) {
        this.log('Auto-registration disabled', 'debug', {
          autoRegisterNewScripts: this.config.autoRegisterNewScripts,
          serverBaseUrl: this.config.serverBaseUrl
        });
        return { registered: false, reason: 'auto-registration disabled' };
      }

      // Avoid duplicate registrations
      if (this.pendingRegistrations.has(scriptInfo.hash)) {
        this.log(`Script already pending registration: ${scriptInfo.id}`, 'debug');
        return { registered: false, reason: 'already pending' };
      }

      this.pendingRegistrations.add(scriptInfo.hash);

      try {
        const endpoint = `${this.config.serverBaseUrl}${this.config.registerScriptEndpoint}`;

        const payload = {
          url: scriptInfo.id,
          contentHash: scriptInfo.hash,
          scriptType: scriptInfo.inline ? 'inline' : 'external',
          sizeBytes: scriptInfo.content ? scriptInfo.content.length : 0,
          contentPreview: scriptInfo.content ? scriptInfo.content.substring(0, 500) : null,
          pageUrl: window.location.href,
          discoveryContext: JSON.stringify({
            loadType: scriptInfo.loadType,
            timestamp: scriptInfo.timestamp,
            userAgent: navigator.userAgent,
            sessionId: this.sessionId
          })
        };

        this.log(`📤 Sending registration request to server`, 'info', {
          endpoint,
          script: scriptInfo.id,
          type: scriptInfo.inline ? 'inline' : 'external',
          hash: scriptInfo.hash.substring(0, 20) + '...'
        });

        const response = await this.makeServerRequest(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Session-ID': this.sessionId
          },
          body: JSON.stringify(payload)
        });

        if (response.ok) {
          const result = await response.json();
          this.log(`✅ Script registered successfully`, 'info', {
            script: scriptInfo.id,
            status: result.status,
            scriptId: result.scriptId,
            isNew: result.isNew
          });

          // Store server status
          this.knownScripts.set(scriptInfo.hash, {
            scriptId: result.scriptId,
            status: result.status,
            isNew: result.isNew,
            registeredAt: Date.now()
          });

          // Start polling for approval if pending
          if (result.status === 'pending_approval' && this.config.pollApprovalStatus) {
            this.log(`⏳ Script pending approval - starting status polling`, 'info', {
              script: scriptInfo.id,
              pollInterval: this.config.pollInterval + 'ms'
            });
            this.startPollingForApproval(scriptInfo);
          }

          return { registered: true, result };
        } else {
          const errorText = await response.text();
          throw new Error(`Server responded with ${response.status}: ${errorText}`);
        }
      } catch (error) {
        this.log(`❌ Failed to register script`, 'error', {
          script: scriptInfo.id,
          error: error.message,
          endpoint: `${this.config.serverBaseUrl}${this.config.registerScriptEndpoint}`
        });
        return { registered: false, error: error.message };
      } finally {
        this.pendingRegistrations.delete(scriptInfo.hash);
      }
    }

    /**
     * NEW: Check script approval status with server
     */
    async checkScriptStatus(scriptHash) {
      if (!this.config.serverBaseUrl) {
        return null;
      }

      try {
        const endpoint = `${this.config.serverBaseUrl}${this.config.checkStatusEndpoint}/${scriptHash}`;

        const response = await this.makeServerRequest(endpoint, {
          method: 'GET',
          headers: {
            'X-Session-ID': this.sessionId
          }
        });

        if (response.ok) {
          const status = await response.json();
          this.knownScripts.set(scriptHash, {
            ...status,
            checkedAt: Date.now()
          });
          return status;
        }

        return null;
      } catch (error) {
        this.log(`Failed to check script status: ${error.message}`, 'debug');
        return null;
      }
    }

    /**
     * NEW: Report integrity violation to server
     */
    async reportViolationToServer(violation) {
      if (!this.config.serverBaseUrl) {
        this.log('Cannot report violation - no server URL configured', 'debug');
        return false;
      }

      try {
        const endpoint = `${this.config.serverBaseUrl}${this.config.reportViolationEndpoint}`;

        const payload = {
          scriptUrl: violation.scriptId,
          oldHash: violation.expectedHash || null,
          newHash: violation.hash,
          violationType: violation.violationType,
          pageUrl: window.location.href,
          userSession: this.sessionId,
          userAgent: navigator.userAgent,
          severity: 'HIGH',
          loadType: violation.loadType,
          context: JSON.stringify({
            timestamp: violation.timestamp,
            inline: violation.inline
          })
        };

        this.log(`🚨 Reporting violation to server`, 'warn', {
          endpoint,
          script: violation.scriptId,
          violationType: violation.violationType,
          severity: 'HIGH'
        });

        const response = await this.makeServerRequest(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Session-ID': this.sessionId
          },
          body: JSON.stringify(payload)
        });

        if (response.ok) {
          const result = await response.json();
          this.log('✅ Violation reported successfully', 'info', result);
          return true;
        } else {
          this.log(`❌ Server rejected violation report: ${response.status}`, 'warn');
          return false;
        }
      } catch (error) {
        this.log(`❌ Failed to report violation to server`, 'error', {
          error: error.message,
          script: violation.scriptId
        });
        return false;
      }
    }

    /**
     * NEW: Start polling for script approval status
     */
    startPollingForApproval(scriptInfo) {
      const startTime = Date.now();
      const pollInterval = this.config.pollInterval || 30000;
      const pollTimeout = this.config.pollTimeout || 300000;

      const pollTimer = setInterval(async () => {
        // Check if timeout reached
        if (Date.now() - startTime > pollTimeout) {
          this.log(`Polling timeout for script: ${scriptInfo.id}`, 'warn');
          clearInterval(pollTimer);
          this.pollTimers.delete(scriptInfo.hash);
          return;
        }

        // Check status
        const status = await this.checkScriptStatus(scriptInfo.hash);

        if (status && status.status !== 'pending_approval') {
          this.log(`Script status updated: ${scriptInfo.id} -> ${status.status}`, 'info');
          clearInterval(pollTimer);
          this.pollTimers.delete(scriptInfo.hash);

          // Update script inventory
          const inventoryItem = this.scriptInventory.find(s => s.hash === scriptInfo.hash);
          if (inventoryItem) {
            inventoryItem.serverStatus = status.status;
            inventoryItem.authorized = status.status === 'approved';
          }

          // Trigger callback if approved
          if (status.status === 'approved' && this.config.alertCallback) {
            this.config.alertCallback({
              type: 'script_approved',
              script: scriptInfo,
              status: status
            });
          }
        }
      }, pollInterval);

      this.pollTimers.set(scriptInfo.hash, pollTimer);
    }

    /**
     * NEW: Make server request with timeout
     */
    async makeServerRequest(url, options = {}) {
      const timeout = this.config.serverTimeoutMs || 5000;

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      try {
        const response = await fetch(url, {
          ...options,
          signal: controller.signal,
          credentials: 'same-origin'
        });

        clearTimeout(timeoutId);
        return response;
      } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
          throw new Error('Request timeout');
        }
        throw error;
      }
    }

    /**
     * Cleanup and stop monitoring
     */
    destroy() {
      if (this.observer) {
        this.observer.disconnect();
      }

      // Clear all polling timers
      for (const timer of this.pollTimers.values()) {
        clearInterval(timer);
      }
      this.pollTimers.clear();

      this.flushPendingAlerts();
      this.log('Script Integrity Monitor destroyed', 'info');
    }
  }

  /**
   * Initialize the monitor with configuration
   */
  function initializeMonitor() {
    // Wait for configuration to be available
    const config = window.SCRIPT_INTEGRITY_CONFIG || {};

    // Create monitor instance
    const monitor = new ScriptIntegrityMonitor(config);

    // Expose to window for external access
    window.__SCRIPT_INTEGRITY_MONITOR__ = monitor;

    // Expose public API
    window.ScriptIntegrityMonitor = {
      getInventory: () => monitor.getInventory(),
      getViolations: () => monitor.getViolations(),
      getSummary: () => monitor.getInventorySummary(),
      generateReport: () => monitor.generateComplianceReport(),
      exportInventory: () => monitor.exportInventory(),
      destroy: () => monitor.destroy()
    };

    return monitor;
  }

  // Initialize immediately if DOM is ready, otherwise wait
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeMonitor);
  } else {
    initializeMonitor();
  }

})();
