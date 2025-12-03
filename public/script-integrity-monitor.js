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
        debug: config.debug !== false,

        // Server integration configuration
        serverBaseUrl: config.serverBaseUrl || null,
        registerScriptEndpoint: config.registerScriptEndpoint || '/api/scripts/register',
        checkStatusEndpoint: config.checkStatusEndpoint || '/api/scripts/status',
        reportViolationEndpoint: config.reportViolationEndpoint || '/api/scripts/violation',
        autoRegisterNewScripts: config.autoRegisterNewScripts !== false,
        pollApprovalStatus: config.pollApprovalStatus !== false,
        pollInterval: config.pollInterval || 30000,
        pollTimeout: config.pollTimeout || 300000,
        fallbackMode: config.fallbackMode || 'report',
        serverTimeoutMs: config.serverTimeoutMs || 5000
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

      // Blocked scripts tracking (for enforcement mode)
      this.blockedScripts = new Set();        // Set of blocked script hashes and URLs

      // Store original DOM methods to prevent bypass attacks
      this.originalMethods = {
        createElement: document.createElement.bind(document),
        appendChild: Element.prototype.appendChild,
        insertBefore: Element.prototype.insertBefore,
        replaceChild: Element.prototype.replaceChild
      };

      // Initialize monitoring
      this.initialize();
    }

    /**
     * Initialize the integrity monitoring system
     */
    async initialize() {
      this.log('Initializing Script Integrity Monitor', 'info');
      this.log(`Mode: ${this.config.mode}`, 'info');
      this.log(`Hash Algorithm: ${this.config.hashAlgorithm}`, 'info');

      // Log server integration status
      if (this.config.serverBaseUrl) {
        this.log(`✅ Server Integration: ENABLED`, 'info', {
          serverBaseUrl: this.config.serverBaseUrl,
          autoRegister: this.config.autoRegisterNewScripts,
          pollApproval: this.config.pollApprovalStatus
        });
      } else {
        this.log(`⚠️  Server Integration: DISABLED (no serverBaseUrl)`, 'warn', {
          currentPage: window.location.href,
          protocol: window.location.protocol
        });
      }

      // Check for Web Crypto API support
      if (!window.crypto || !window.crypto.subtle) {
        this.log('Web Crypto API not supported - monitoring disabled', 'error');
        return;
      }

      // Scan existing scripts on the page
      await this.scanExistingScripts();

      // Set up MutationObserver for dynamically added scripts
      if (this.config.monitorDynamicScripts) {
        this.setupMutationObserver();
      }

      // Set up DOM method overrides to intercept dynamic script injection
      if (this.config.monitorDynamicScripts) {
        this.setupDOMMethodOverrides();
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
    async scanExistingScripts() {
      const scripts = document.querySelectorAll('script');
      this.log(`Found ${scripts.length} existing script(s)`, 'debug');

      // Process scripts sequentially to ensure proper initialization
      let index = 0;
      for (const script of scripts) {
        // Skip this monitoring script itself
        if (script === document.currentScript) {
          this.log('Skipping monitoring script itself', 'debug');
          continue;
        }

        await this.processScript(script, 'initial-load', index);
        index++;
      }

      this.log(`Processed ${index} script(s)`, 'debug');
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
              // In enforce mode, block script immediately if it's in the block list
              if (this.config.mode === 'enforce' && this.blockedScripts) {
                const src = node.src || null;

                // Check if this script is in the block list
                if (src && this.blockedScripts.has(src)) {
                  this.log(`🚫 Blocking previously rejected script: ${src}`, 'warn');
                  node.type = 'blocked-by-integrity-monitor';
                  node.setAttribute('data-integrity-status', 'blocked');
                  node.setAttribute('data-blocked-reason', 'Previously rejected by administrator');

                  if (node.parentNode) {
                    node.parentNode.removeChild(node);
                  }

                  console.error('[SIM] ❌ Blocked script from loading (previously rejected):', src);
                  return; // Don't process further
                }
              }

              this.processScript(node, 'dynamic-addition');
            }

            // Check if added node contains scripts (e.g., div with scripts)
            if (node.querySelectorAll) {
              const scripts = node.querySelectorAll('script');
              scripts.forEach((script) => {
                // In enforce mode, check block list first
                if (this.config.mode === 'enforce' && this.blockedScripts) {
                  const src = script.src || null;

                  if (src && this.blockedScripts.has(src)) {
                    this.log(`🚫 Blocking previously rejected nested script: ${src}`, 'warn');
                    script.type = 'blocked-by-integrity-monitor';
                    script.setAttribute('data-integrity-status', 'blocked');
                    script.setAttribute('data-blocked-reason', 'Previously rejected by administrator');

                    if (script.parentNode) {
                      script.parentNode.removeChild(script);
                    }

                    console.error('[SIM] ❌ Blocked nested script from loading (previously rejected):', src);
                    return;
                  }
                }

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
     * Set up DOM method overrides to intercept dynamic script injection
     * This catches scripts created via document.createElement() and inserted via
     * appendChild(), insertBefore(), or replaceChild()
     */
    setupDOMMethodOverrides() {
      const self = this;

      this.log('Setting up DOM method overrides for script interception', 'debug');

      // Override document.createElement to intercept script element creation
      document.createElement = function(tagName, options) {
        const element = self.originalMethods.createElement(tagName, options);

        // If creating a script element, monitor its src attribute
        if (tagName && tagName.toLowerCase() === 'script') {
          self.log('🔍 Intercepted createElement("script")', 'debug');

          // Store reference to original setAttribute
          const originalSetAttribute = element.setAttribute.bind(element);
          const originalSetSrc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');

          // Override setAttribute to catch src attribute changes
          element.setAttribute = function(name, value) {
            if (name === 'src') {
              self.log(`🔍 Script src set via setAttribute: ${value}`, 'debug');

              // Check if this script should be blocked
              if (self.shouldBlockDynamicScript(value, element)) {
                self.log(`🚫 Blocked dynamic script via createElement: ${value}`, 'warn');
                element.setAttribute('data-integrity-status', 'blocked');
                element.setAttribute('data-blocked-reason', 'Blocked by integrity monitor');
                element.type = 'blocked-by-integrity-monitor';
                return;
              }
            }
            return originalSetAttribute(name, value);
          };

          // Override src property setter
          Object.defineProperty(element, 'src', {
            set: function(value) {
              self.log(`🔍 Script src set via property: ${value}`, 'debug');

              if (self.shouldBlockDynamicScript(value, element)) {
                self.log(`🚫 Blocked dynamic script via createElement (property): ${value}`, 'warn');
                element.setAttribute('data-integrity-status', 'blocked');
                element.setAttribute('data-blocked-reason', 'Blocked by integrity monitor');
                element.type = 'blocked-by-integrity-monitor';
                return;
              }

              originalSetSrc.set.call(this, value);
            },
            get: function() {
              return originalSetSrc.get.call(this);
            },
            configurable: true
          });

          // Mark element as monitored
          element.setAttribute('data-dynamic-script', 'true');
        }

        return element;
      };

      // Override appendChild to intercept script insertion
      Element.prototype.appendChild = function(child) {
        if (child && child.nodeName === 'SCRIPT') {
          self.log('🔍 Intercepted appendChild(script)', 'debug');

          const src = child.src || child.getAttribute('src');
          const content = child.textContent;

          if (self.shouldBlockDynamicScript(src || content, child)) {
            self.log(`🚫 Blocked script via appendChild: ${src || 'inline script'}`, 'warn');

            // Don't append the script
            child.setAttribute('data-integrity-status', 'blocked');
            child.setAttribute('data-blocked-reason', 'Blocked by integrity monitor');
            child.type = 'blocked-by-integrity-monitor';

            // Return the child without appending (still need to return for API compatibility)
            return child;
          }
        }

        return self.originalMethods.appendChild.call(this, child);
      };

      // Override insertBefore to intercept script insertion
      Element.prototype.insertBefore = function(newNode, referenceNode) {
        if (newNode && newNode.nodeName === 'SCRIPT') {
          self.log('🔍 Intercepted insertBefore(script)', 'debug');

          const src = newNode.src || newNode.getAttribute('src');
          const content = newNode.textContent;

          if (self.shouldBlockDynamicScript(src || content, newNode)) {
            self.log(`🚫 Blocked script via insertBefore: ${src || 'inline script'}`, 'warn');

            newNode.setAttribute('data-integrity-status', 'blocked');
            newNode.setAttribute('data-blocked-reason', 'Blocked by integrity monitor');
            newNode.type = 'blocked-by-integrity-monitor';

            return newNode;
          }
        }

        return self.originalMethods.insertBefore.call(this, newNode, referenceNode);
      };

      // Override replaceChild to intercept script replacement
      Element.prototype.replaceChild = function(newChild, oldChild) {
        if (newChild && newChild.nodeName === 'SCRIPT') {
          self.log('🔍 Intercepted replaceChild(script)', 'debug');

          const src = newChild.src || newChild.getAttribute('src');
          const content = newChild.textContent;

          if (self.shouldBlockDynamicScript(src || content, newChild)) {
            self.log(`🚫 Blocked script via replaceChild: ${src || 'inline script'}`, 'warn');

            newChild.setAttribute('data-integrity-status', 'blocked');
            newChild.setAttribute('data-blocked-reason', 'Blocked by integrity monitor');
            newChild.type = 'blocked-by-integrity-monitor';

            return newChild;
          }
        }

        return self.originalMethods.replaceChild.call(this, newChild, oldChild);
      };

      this.log('✅ DOM method overrides installed successfully', 'info');
    }

    /**
     * Check if a dynamically created/inserted script should be blocked
     * @param {string} srcOrContent - Script src URL or inline content
     * @param {HTMLScriptElement} scriptElement - The script element
     * @returns {boolean} True if script should be blocked
     */
    shouldBlockDynamicScript(srcOrContent, scriptElement) {
      // Only block in enforce mode
      if (this.config.mode !== 'enforce') {
        return false;
      }

      // If we have a src URL, check against blocked scripts
      if (srcOrContent && typeof srcOrContent === 'string') {
        // Check if this script source is in the blocked list
        if (this.blockedScripts.has(srcOrContent)) {
          return true;
        }

        // Check if URL matches any blocked pattern
        for (const blockedItem of this.blockedScripts) {
          // Ensure blockedItem is a string before calling includes()
          if (blockedItem && typeof blockedItem === 'string') {
            if (srcOrContent.includes(blockedItem) || blockedItem.includes(srcOrContent)) {
              return true;
            }
          }
        }
      }

      // Default: allow script (will be processed by MutationObserver)
      // This prevents double-blocking while still allowing monitoring
      return false;
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
        id: await this.generateScriptId(script, index),
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
        const verification = await this.verifyIntegrity(scriptInfo);
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
     * @param {number} index - Script index/position in page
     * @returns {Promise<string>} Unique identifier
     */
    async generateScriptId(script, index = 0) {
      if (script.src) {
        // Use URL for external scripts
        const url = new URL(script.src, window.location.href);
        return url.href;
      } else {
        // For inline scripts, use position-based naming so variations share the same URL
        return `inline-script-position-${index}`;
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
          this.log(`Checking server status for: ${scriptInfo.id}`, 'debug');
          const serverStatus = await this.checkScriptStatus(encodeURIComponent(scriptInfo.hash));

          if (serverStatus) {
            result.serverStatus = serverStatus.status;

            if (serverStatus.status === 'approved') {
              result.authorized = true;
              this.log(`Script approved on server: ${scriptInfo.id}`, 'info');
              // Remove any existing violations for this approved script
              this.violations = this.violations.filter(v => 
                v.hash !== scriptInfo.hash && 
                v.scriptId !== scriptInfo.id
              );
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
            this.log(`🆕 New script discovered: ${scriptInfo.id}`, 'info');

            // Auto-register with server
            if (this.config.autoRegisterNewScripts) {
              this.log(`🚀 Attempting auto-registration for: ${scriptInfo.id}`, 'info');
              const regResult = await this.registerNewScript(scriptInfo);
              this.log(`Registration result:`, 'debug', regResult);
            } else {
              this.log(`⚠️  Auto-registration disabled - script not registered`, 'warn');
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
      if (this.config.serverBaseUrl) {
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

      // In enforce mode, block scripts based on violation type
      // Block security violations and admin-rejected scripts
      // Do NOT block pending approval or newly discovered scripts (allow time for review)
      const blockableViolations = [
        'HASH_MISMATCH',
        'SRI_MISMATCH',
        'REJECTED_BY_ADMIN',
        'NO_BASELINE_HASH',
        'UNAUTHORIZED_SCRIPT'
      ];

      const shouldBlock = this.config.mode === 'enforce' &&
                         blockableViolations.includes(scriptInfo.violation);

      if (shouldBlock) {
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
      this.log(`🚫 Blocking script: ${scriptInfo.id} (${scriptInfo.violation})`, 'warn');

      // This is a best-effort approach
      // For inline scripts that have already executed, we cannot undo execution
      // For external scripts, we can prevent execution if caught early enough

      try {
        // Find the script element in the DOM
        let scriptElement = null;

        if (scriptInfo.inline) {
          // Find inline script by content hash or position
          const scripts = document.querySelectorAll('script:not([src])');
          for (let i = 0; i < scripts.length; i++) {
            const content = scripts[i].textContent || scripts[i].innerHTML;
            if (content === scriptInfo.content ||
                (scriptInfo.context && scriptInfo.context.position === i)) {
              scriptElement = scripts[i];
              break;
            }
          }
        } else if (scriptInfo.src) {
          // Find external script by src
          scriptElement = document.querySelector(`script[src="${scriptInfo.src}"]`);
        }

        if (scriptElement) {
          // Method 1: Change type to prevent execution (for scripts not yet executed)
          if (scriptElement.type === 'text/javascript' || scriptElement.type === '' || !scriptElement.type) {
            scriptElement.type = 'blocked-by-integrity-monitor';
            this.log(`Changed script type to prevent execution: ${scriptInfo.id}`, 'info');
          }

          // Method 2: Remove script from DOM
          if (scriptElement.parentNode) {
            // Mark as blocked before removing
            scriptElement.setAttribute('data-integrity-status', 'blocked');
            scriptElement.setAttribute('data-violation-type', scriptInfo.violation);
            scriptElement.setAttribute('data-blocked-timestamp', new Date().toISOString());

            // For rejected scripts, add a visible comment/marker
            if (scriptInfo.violation === 'REJECTED_BY_ADMIN') {
              const marker = document.createComment(
                `SCRIPT BLOCKED BY ADMINISTRATOR - ${scriptInfo.id} - Reason: Script rejected during security review`
              );
              scriptElement.parentNode.insertBefore(marker, scriptElement);
              this.log(`🔒 Admin-rejected script blocked: ${scriptInfo.id}`, 'warn');
            }

            // Remove from DOM
            scriptElement.parentNode.removeChild(scriptElement);
            this.log(`Removed script element from DOM: ${scriptInfo.id}`, 'info');
          }
        } else {
          this.log(`Script element not found in DOM (may have already executed): ${scriptInfo.id}`, 'warn');
        }

        // Method 3: Add to block list to prevent future dynamic loads
        if (!this.blockedScripts) {
          this.blockedScripts = new Set();
        }
        // Only add non-null/undefined values to the Set
        if (scriptInfo.hash) {
          this.blockedScripts.add(scriptInfo.hash);
        }
        if (scriptInfo.src) {
          this.blockedScripts.add(scriptInfo.src);
        }

        // Log the blocking
        console.error('[SIM] ❌ SCRIPT BLOCKED (enforcement mode):', {
          scriptId: scriptInfo.id,
          violation: scriptInfo.violation,
          src: scriptInfo.src || '(inline)',
          timestamp: new Date().toISOString()
        });

        // For REJECTED_BY_ADMIN, also log to console with distinct styling
        if (scriptInfo.violation === 'REJECTED_BY_ADMIN') {
          console.error(
            '%c[SIM] 🛑 ADMINISTRATOR BLOCKED SCRIPT',
            'background: #d32f2f; color: white; font-weight: bold; padding: 4px 8px; border-radius: 3px;',
            `\nScript: ${scriptInfo.id}\nReason: Rejected by administrator during security review\nAction: Script execution prevented and removed from page`
          );
        }

      } catch (error) {
        this.log(`Error blocking script ${scriptInfo.id}: ${error.message}`, 'error');
        console.error('[SIM] Error blocking script:', error);
      }
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
      const unauthorizedScripts = this.scriptInventory.filter(s => 
        !s.authorized && 
        s.violation !== 'NEW_SCRIPT' && 
        s.violation !== 'PENDING_APPROVAL'
      ).length;

      return {
        totalScripts: this.scriptInventory.length,
        authorizedScripts: this.scriptInventory.filter(s => s.authorized).length,
        unauthorizedScripts: unauthorizedScripts,
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
     * @param {boolean} includePending - Include PENDING_APPROVAL and NEW_SCRIPT (default: false)
     * @returns {Array} All violations (excluding pending approvals by default)
     */
    getViolations(includePending = false) {
      if (includePending) {
        return this.violations;
      }
      // Filter out PENDING_APPROVAL and NEW_SCRIPT - these are not security violations
      return this.violations.filter(v => 
        v.violationType !== 'PENDING_APPROVAL' && 
        v.violationType !== 'NEW_SCRIPT'
      );
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
        violations: this.getViolations(true).map(v => ({
          ...v,
          timestamp: new Date(v.timestamp).toISOString()
        })),
        complianceStatus: this.getViolations(false).length === 0 ? 'COMPLIANT' : 'VIOLATIONS_DETECTED'
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
          scriptPosition: scriptInfo.inline ? scriptInfo.index : null,  // NEW: Track inline script position
          discoveryContext: JSON.stringify({
            loadType: scriptInfo.loadType,
            timestamp: scriptInfo.timestamp,
            userAgent: navigator.userAgent,
            sessionId: this.sessionId,
            scriptIndex: scriptInfo.index  // Include index in context as well
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
        this.log('Cannot check status - no server URL', 'debug');
        return null;
      }

      try {
        const endpoint = `${this.config.serverBaseUrl}${this.config.checkStatusEndpoint}/${scriptHash}`;

        this.log(`Checking status: GET ${endpoint}`, 'debug');

        const response = await this.makeServerRequest(endpoint, {
          method: 'GET',
          headers: {
            'X-Session-ID': this.sessionId
          }
        });

        if (response.ok) {
          const status = await response.json();
          this.log(`✅ Status check success: ${status.status}`, 'debug', status);
          this.knownScripts.set(scriptHash, {
            ...status,
            checkedAt: Date.now()
          });
          return status;
        } else {
          this.log(`📭 Script not found on server (${response.status})`, 'debug');
          return null;
        }
      } catch (error) {
        this.log(`❌ Failed to check script status: ${error.message}`, 'warn', {
          error: error.message,
          endpoint: `${this.config.serverBaseUrl}${this.config.checkStatusEndpoint}/${scriptHash}`
        });
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

          // If approved, remove from violations array
          if (status.status === 'approved') {
            this.violations = this.violations.filter(v => 
              v.hash !== scriptInfo.hash && 
              v.scriptId !== scriptInfo.id
            );
            this.log(`Removed approved script from violations: ${scriptInfo.id}`, 'info');
          }

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
   * Auto-load monitoring modules based on configuration
   */
  function autoLoadMonitoringModules(config) {
    const modulesToLoad = [];

    // Check if header monitoring should be enabled
    if (config.monitorHeaders !== false) {
      modulesToLoad.push({
        name: 'HTTP Header Monitor',
        src: 'http-header-monitor.js',
        checkExisting: () => window.HttpHeaderMonitor !== undefined
      });
    }

    // Check if network monitoring should be enabled
    if (config.monitorNetworkRequests !== false) {
      modulesToLoad.push({
        name: 'Network Request Monitor',
        src: 'network-request-monitor.js',
        checkExisting: () => window.NetworkRequestMonitor !== undefined
      });
    }

    // Load each module that isn't already loaded
    modulesToLoad.forEach(module => {
      if (!module.checkExisting()) {
        const script = document.createElement('script');
        script.src = module.src;
        script.async = false; // Load in order
        script.onload = () => {
          console.log(`[SIM] Auto-loaded: ${module.name}`);
        };
        script.onerror = () => {
          console.warn(`[SIM] Failed to auto-load: ${module.name}`);
        };
        document.head.appendChild(script);
      } else {
        console.log(`[SIM] ${module.name} already loaded, skipping auto-load`);
      }
    });
  }

  /**
   * Initialize the monitor with configuration
   */
  function initializeMonitor() {
    // Wait for configuration to be available
    const config = window.SCRIPT_INTEGRITY_CONFIG || {};

    // Auto-load monitoring modules
    autoLoadMonitoringModules(config);

    // Create monitor instance
    const monitor = new ScriptIntegrityMonitor(config);

    // Expose to window for external access
    window.__SCRIPT_INTEGRITY_MONITOR__ = monitor;

    // Expose public API
    window.ScriptIntegrityMonitor = {
      getInventory: () => monitor.getInventory(),
      getViolations: (includePending) => monitor.getViolations(includePending),
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
