/**
 * Network Request Monitor - PCI DSS v4.0.1 Requirement 11.6.1
 *
 * Monitors network requests from payment pages to detect unauthorized
 * data exfiltration attempts and rogue script communications.
 *
 * @version 1.0.0
 * @license MIT
 */

(function() {
  'use strict';

  // Prevent multiple initialization
  if (window.__NETWORK_REQUEST_MONITOR__) {
    console.warn('[Network Monitor] Already initialized');
    return;
  }

  /**
   * Network Request Monitor Class
   * Intercepts and validates all network requests
   */
  class NetworkRequestMonitor {
    constructor(config = {}) {
      this.config = {
        // Whitelisted destinations
        allowedDomains: config.allowedDomains || [],
        allowedEndpoints: config.allowedEndpoints || [],

        // Server integration
        serverBaseUrl: config.serverBaseUrl || null,
        reportViolationEndpoint: config.reportViolationEndpoint || '/api/network/violation',

        // Monitoring options
        monitorFetch: config.monitorFetch !== false,
        monitorXHR: config.monitorXHR !== false,
        monitorBeacon: config.monitorBeacon !== false,
        monitorFormSubmit: config.monitorFormSubmit !== false,

        // Enforcement mode
        mode: config.mode || 'report', // 'report' or 'enforce'

        // Debug mode
        debug: config.debug !== false
      };

      // Store original methods
      this.originalMethods = {
        fetch: window.fetch.bind(window),
        XMLHttpRequest: window.XMLHttpRequest,
        sendBeacon: navigator.sendBeacon ? navigator.sendBeacon.bind(navigator) : null
      };

      // Violation tracking
      this.violations = [];

      // Request log
      this.requestLog = [];

      // Session ID
      this.sessionId = this.generateSessionId();

      // Initialize
      this.initialize();
    }

    /**
     * Initialize network monitoring
     */
    initialize() {
      this.log('Initializing Network Request Monitor', 'info');

      try {
        if (this.config.monitorFetch) {
          this.setupFetchInterceptor();
        }

        if (this.config.monitorXHR) {
          this.setupXHRInterceptor();
        }

        if (this.config.monitorBeacon) {
          this.setupBeaconInterceptor();
        }

        if (this.config.monitorFormSubmit) {
          this.setupFormSubmitMonitor();
        }

        this.log('Network Request Monitor initialized successfully', 'info');
      } catch (error) {
        this.log(`Initialization error: ${error.message}`, 'error');
      }
    }

    /**
     * Setup fetch() interceptor
     */
    setupFetchInterceptor() {
      const self = this;

      window.fetch = function(...args) {
        const url = args[0];
        const options = args[1] || {};

        // Inspect request before execution
        const allowed = self.inspectRequest('fetch', url, options);

        if (!allowed && self.config.mode === 'enforce') {
          self.log(`🚫 Blocked fetch request: ${url}`, 'warn');
          return Promise.reject(new Error('Request blocked by Network Monitor'));
        }

        // Execute original fetch
        return self.originalMethods.fetch.apply(this, args);
      };

      this.log('Fetch interceptor installed', 'debug');
    }

    /**
     * Setup XMLHttpRequest interceptor
     */
    setupXHRInterceptor() {
      const self = this;
      const OriginalXHR = this.originalMethods.XMLHttpRequest;

      window.XMLHttpRequest = function() {
        const xhr = new OriginalXHR();

        // Store original open
        const originalOpen = xhr.open;

        xhr.open = function(method, url, ...rest) {
          // Inspect request
          const allowed = self.inspectRequest('xhr', url, { method });

          if (!allowed && self.config.mode === 'enforce') {
            self.log(`🚫 Blocked XHR request: ${url}`, 'warn');
            throw new Error('Request blocked by Network Monitor');
          }

          // Call original open
          return originalOpen.apply(this, [method, url, ...rest]);
        };

        return xhr;
      };

      // Copy properties
      for (const prop in OriginalXHR) {
        if (OriginalXHR.hasOwnProperty(prop)) {
          window.XMLHttpRequest[prop] = OriginalXHR[prop];
        }
      }

      this.log('XHR interceptor installed', 'debug');
    }

    /**
     * Setup sendBeacon() interceptor
     */
    setupBeaconInterceptor() {
      if (!navigator.sendBeacon) {
        return;
      }

      const self = this;

      navigator.sendBeacon = function(url, data) {
        // Inspect request
        const allowed = self.inspectRequest('beacon', url, { data });

        if (!allowed && self.config.mode === 'enforce') {
          self.log(`🚫 Blocked beacon: ${url}`, 'warn');
          return false;
        }

        // Execute original sendBeacon
        return self.originalMethods.sendBeacon(url, data);
      };

      this.log('Beacon interceptor installed', 'debug');
    }

    /**
     * Setup form submit monitoring
     */
    setupFormSubmitMonitor() {
      const self = this;

      document.addEventListener('submit', function(event) {
        const form = event.target;
        const actionUrl = form.action;

        // Only check forms (not other submittable elements)
        if (form.tagName !== 'FORM') {
          return;
        }

        // Inspect form submission
        const allowed = self.inspectRequest('form', actionUrl, {
          method: form.method,
          formId: form.id,
          formName: form.name
        });

        if (!allowed && self.config.mode === 'enforce') {
          event.preventDefault();
          self.log(`🚫 Blocked form submission: ${actionUrl}`, 'warn');
          alert('Form submission blocked - unauthorized destination');
        }
      }, true); // Use capture phase

      this.log('Form submit monitor installed', 'debug');
    }

    /**
     * Inspect network request
     * @param {string} type - Request type (fetch, xhr, beacon, form)
     * @param {string} url - Destination URL
     * @param {object} options - Request options
     * @returns {boolean} - True if allowed, false if blocked
     */
    inspectRequest(type, url, options = {}) {
      this.log(`Inspecting ${type} request: ${url}`, 'debug');

      // Parse URL
      let destinationUrl;
      try {
        destinationUrl = new URL(url, window.location.href);
      } catch (error) {
        this.log(`Invalid URL: ${url}`, 'warn');
        return true; // Allow malformed URLs (will fail anyway)
      }

      // Log request
      this.requestLog.push({
        type,
        url: destinationUrl.href,
        destination: destinationUrl.origin,
        timestamp: new Date().toISOString(),
        options
      });

      // Check if destination is allowed
      const isAllowed = this.isAllowedDestination(destinationUrl);

      if (!isAllowed) {
        // Create violation
        const violation = {
          type: 'UNAUTHORIZED_REQUEST',
          requestType: type,
          destinationUrl: destinationUrl.href,
          destinationOrigin: destinationUrl.origin,
          sourceUrl: window.location.href,
          timestamp: new Date().toISOString(),
          severity: 'CRITICAL',
          blocked: this.config.mode === 'enforce'
        };

        this.violations.push(violation);

        // Report violation
        this.reportViolation(violation);

        return false;
      }

      return true;
    }

    /**
     * Check if destination is allowed
     * @param {URL} url - Destination URL object
     * @returns {boolean} - True if allowed
     */
    isAllowedDestination(url) {
      // Same origin is always allowed
      if (url.origin === window.location.origin) {
        return true;
      }

      // Check against allowed domains
      for (const domain of this.config.allowedDomains) {
        if (typeof domain === 'string') {
          if (url.origin === domain || url.hostname === domain) {
            return true;
          }
        } else if (domain instanceof RegExp) {
          if (domain.test(url.href) || domain.test(url.origin)) {
            return true;
          }
        }
      }

      // Check against allowed endpoints
      for (const endpoint of this.config.allowedEndpoints) {
        if (typeof endpoint === 'string') {
          if (url.pathname === endpoint) {
            return true;
          }
        } else if (endpoint instanceof RegExp) {
          if (endpoint.test(url.pathname)) {
            return true;
          }
        }
      }

      // Not in whitelist
      return false;
    }

    /**
     * Report violation to server
     */
    async reportViolation(violation) {
      if (!this.config.serverBaseUrl) {
        return;
      }

      try {
        const response = await this.originalMethods.fetch(
          `${this.config.serverBaseUrl}${this.config.reportViolationEndpoint}`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              violation,
              sessionId: this.sessionId,
              userAgent: navigator.userAgent,
              timestamp: new Date().toISOString()
            })
          }
        );

        if (response.ok) {
          this.log(`Reported ${violation.type} for: ${violation.destinationUrl}`, 'info');
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
      const prefix = '🌐 [Network Monitor]';
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
     * Get monitoring status
     */
    getStatus() {
      return {
        mode: this.config.mode,
        requestCount: this.requestLog.length,
        violationCount: this.violations.length,
        allowedDomains: this.config.allowedDomains.length,
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
     * Get request log
     */
    getRequestLog() {
      return [...this.requestLog];
    }
  }

  // Export to global scope
  window.NetworkRequestMonitor = NetworkRequestMonitor;

  // Mark as initialized
  window.__NETWORK_REQUEST_MONITOR__ = true;

  // Auto-initialize if config is present
  if (window.NETWORK_REQUEST_MONITOR_CONFIG) {
    const monitor = new NetworkRequestMonitor(window.NETWORK_REQUEST_MONITOR_CONFIG);
    window.__NETWORK_REQUEST_MONITOR_INSTANCE__ = monitor;
  }

})();
