/**
 * HTTP Header Monitor - PCI DSS v4.0.1 Requirement 11.6.1
 *
 * Monitors HTTP response headers for tampering and unauthorized modifications.
 * Detects changes to critical security headers that could enable attacks.
 *
 * @version 1.0.0
 * @license MIT
 */

(function() {
  'use strict';

  // Prevent multiple initialization
  if (window.__HTTP_HEADER_MONITOR__) {
    console.warn('[HTTP Header Monitor] Already initialized');
    return;
  }

  /**
   * HTTP Header Monitor Class
   * Monitors and validates HTTP response headers
   */
  class HTTPHeaderMonitor {
    constructor(config = {}) {
      this.config = {
        // Critical security headers to monitor
        criticalHeaders: config.criticalHeaders || [
          'content-security-policy',
          'x-frame-options',
          'x-content-type-options',
          'strict-transport-security',
          'referrer-policy',
          'permissions-policy',
          'x-xss-protection'
        ],

        // Server integration
        serverBaseUrl: config.serverBaseUrl || null,
        registerHeadersEndpoint: config.registerHeadersEndpoint || '/api/headers/register',
        checkHeadersEndpoint: config.checkHeadersEndpoint || '/api/headers/baseline',
        reportViolationEndpoint: config.reportViolationEndpoint || '/api/headers/violation',

        // Monitoring options
        checkInterval: config.checkInterval || 60000, // Check every 60 seconds
        alertOnChange: config.alertOnChange !== false,
        alertOnMissing: config.alertOnMissing !== false,

        // Debug mode
        debug: config.debug !== false
      };

      // Store baseline headers
      this.baselineHeaders = new Map();

      // Store current headers
      this.currentHeaders = new Map();

      // Violation tracking
      this.violations = [];

      // Monitoring state
      this.monitoringActive = false;
      this.checkTimer = null;

      // Session ID
      this.sessionId = this.generateSessionId();

      // Initialize
      this.initialize();
    }

    /**
     * Initialize the header monitoring system
     */
    async initialize() {
      this.log('Initializing HTTP Header Monitor', 'info');

      try {
        // Capture initial headers
        await this.captureHeaders();

        // Fetch baseline from server if configured
        if (this.config.serverBaseUrl) {
          await this.fetchBaseline();
        }

        // Start periodic monitoring
        this.startMonitoring();

        this.log('HTTP Header Monitor initialized successfully', 'info');
      } catch (error) {
        this.log(`Initialization error: ${error.message}`, 'error');
      }
    }

    /**
     * Capture current HTTP headers
     */
    async captureHeaders() {
      this.log('Capturing HTTP headers', 'debug');

      try {
        // Fetch current page headers using HEAD request
        const response = await fetch(window.location.href, {
          method: 'HEAD',
          cache: 'no-cache'
        });

        const headers = new Map();

        // Extract all headers
        for (const [key, value] of response.headers.entries()) {
          const headerName = key.toLowerCase();
          headers.set(headerName, value);
        }

        this.currentHeaders = headers;

        // If no baseline exists, set current as baseline
        if (this.baselineHeaders.size === 0) {
          this.baselineHeaders = new Map(headers);
          this.log(`Captured ${headers.size} headers as baseline`, 'info');
        }

        return headers;
      } catch (error) {
        this.log(`Failed to capture headers: ${error.message}`, 'error');
        throw error;
      }
    }

    /**
     * Fetch baseline headers from server
     */
    async fetchBaseline() {
      if (!this.config.serverBaseUrl) {
        return;
      }

      try {
        const pageUrl = encodeURIComponent(window.location.href);
        const response = await fetch(
          `${this.config.serverBaseUrl}${this.config.checkHeadersEndpoint}/${pageUrl}`,
          {
            method: 'GET',
            headers: {
              'Content-Type': 'application/json'
            }
          }
        );

        if (response.ok) {
          const data = await response.json();

          if (data.headers) {
            this.baselineHeaders = new Map(Object.entries(data.headers));
            this.log(`Loaded ${this.baselineHeaders.size} baseline headers from server`, 'info');
          }
        } else if (response.status === 404) {
          // No baseline exists, register current headers
          await this.registerBaseline();
        }
      } catch (error) {
        this.log(`Failed to fetch baseline: ${error.message}`, 'warn');
      }
    }

    /**
     * Register current headers as baseline with server
     */
    async registerBaseline() {
      if (!this.config.serverBaseUrl) {
        return;
      }

      try {
        const headersObject = Object.fromEntries(this.currentHeaders);

        const response = await fetch(
          `${this.config.serverBaseUrl}${this.config.registerHeadersEndpoint}`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              pageUrl: window.location.href,
              headers: headersObject,
              sessionId: this.sessionId,
              userAgent: navigator.userAgent,
              timestamp: new Date().toISOString()
            })
          }
        );

        if (response.ok) {
          this.log('Registered baseline headers with server', 'info');
        }
      } catch (error) {
        this.log(`Failed to register baseline: ${error.message}`, 'warn');
      }
    }

    /**
     * Start periodic header monitoring
     */
    startMonitoring() {
      if (this.monitoringActive) {
        return;
      }

      this.monitoringActive = true;
      this.log(`Starting periodic monitoring (interval: ${this.config.checkInterval}ms)`, 'info');

      // Perform initial check
      this.checkHeaders();

      // Set up periodic checking
      this.checkTimer = setInterval(() => {
        this.checkHeaders();
      }, this.config.checkInterval);
    }

    /**
     * Stop periodic monitoring
     */
    stopMonitoring() {
      if (this.checkTimer) {
        clearInterval(this.checkTimer);
        this.checkTimer = null;
      }
      this.monitoringActive = false;
      this.log('Monitoring stopped', 'info');
    }

    /**
     * Check headers against baseline
     */
    async checkHeaders() {
      this.log('Checking headers for tampering', 'debug');

      try {
        // Capture current state
        await this.captureHeaders();

        // Compare against baseline
        const violations = this.detectViolations();

        if (violations.length > 0) {
          this.log(`Detected ${violations.length} header violation(s)`, 'warn', violations);

          // Report violations
          for (const violation of violations) {
            await this.reportViolation(violation);
          }
        } else {
          this.log('No header violations detected', 'debug');
        }
      } catch (error) {
        this.log(`Header check failed: ${error.message}`, 'error');
      }
    }

    /**
     * Detect violations by comparing current headers to baseline
     */
    detectViolations() {
      const violations = [];

      // Check critical headers
      for (const headerName of this.config.criticalHeaders) {
        const baselineValue = this.baselineHeaders.get(headerName);
        const currentValue = this.currentHeaders.get(headerName);

        // Header removed
        if (baselineValue && !currentValue) {
          violations.push({
            type: 'HEADER_REMOVED',
            headerName,
            expectedValue: baselineValue,
            actualValue: null,
            severity: 'CRITICAL',
            timestamp: new Date().toISOString()
          });
        }
        // Header modified
        else if (baselineValue && currentValue && baselineValue !== currentValue) {
          violations.push({
            type: 'HEADER_MODIFIED',
            headerName,
            expectedValue: baselineValue,
            actualValue: currentValue,
            severity: 'HIGH',
            timestamp: new Date().toISOString()
          });
        }
        // Critical header missing from start
        else if (!baselineValue && !currentValue && this.config.alertOnMissing) {
          violations.push({
            type: 'HEADER_MISSING',
            headerName,
            expectedValue: null,
            actualValue: null,
            severity: 'MEDIUM',
            timestamp: new Date().toISOString()
          });
        }
      }

      // Store violations
      this.violations.push(...violations);

      return violations;
    }

    /**
     * Report violation to server
     */
    async reportViolation(violation) {
      if (!this.config.serverBaseUrl) {
        return;
      }

      try {
        const response = await fetch(
          `${this.config.serverBaseUrl}${this.config.reportViolationEndpoint}`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              pageUrl: window.location.href,
              violation,
              sessionId: this.sessionId,
              userAgent: navigator.userAgent,
              timestamp: new Date().toISOString()
            })
          }
        );

        if (response.ok) {
          this.log(`Reported ${violation.type} for header: ${violation.headerName}`, 'info');
        }
      } catch (error) {
        this.log(`Failed to report violation: ${error.message}`, 'error');
      }
    }

    /**
     * Generate session ID
     */
    generateSessionId() {
      return `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Logging utility
     */
    log(message, level = 'info', data = null) {
      if (!this.config.debug) {
        return;
      }

      const timestamp = new Date().toISOString();
      const prefix = '🔒 [HTTP Header Monitor]';
      const emoji = level === 'error' ? '❌' : level === 'warn' ? '⚠️' : level === 'info' ? 'ℹ️' : '🔍';

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
    }

    /**
     * Get current status
     */
    getStatus() {
      return {
        monitoring: this.monitoringActive,
        baselineHeaderCount: this.baselineHeaders.size,
        currentHeaderCount: this.currentHeaders.size,
        violationCount: this.violations.length,
        sessionId: this.sessionId
      };
    }

    /**
     * Get all violations
     */
    getViolations() {
      return [...this.violations];
    }

    /**
     * Get baseline headers
     */
    getBaselineHeaders() {
      return Object.fromEntries(this.baselineHeaders);
    }

    /**
     * Get current headers
     */
    getCurrentHeaders() {
      return Object.fromEntries(this.currentHeaders);
    }
  }

  // Export to global scope
  window.HTTPHeaderMonitor = HTTPHeaderMonitor;

  // Mark as initialized
  window.__HTTP_HEADER_MONITOR__ = true;

  // Auto-initialize if config is present
  if (window.HTTP_HEADER_MONITOR_CONFIG) {
    const monitor = new HTTPHeaderMonitor(window.HTTP_HEADER_MONITOR_CONFIG);
    window.__HTTP_HEADER_MONITOR_INSTANCE__ = monitor;
  }

})();
