/**
 * Rate Limiting Middleware
 * Protects API endpoints from abuse
 */

const rateLimit = require('express-rate-limit');

// General rate limiter for most endpoints
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP'
});

// Strict rate limiter for script registration
const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 200, // Max 200 script registrations per hour per session
  keyGenerator: (req) => req.headers['x-session-id'] || req.ip,
  message: 'Too many script registrations from this session'
});

// Rate limiter for violation reports
const violationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  keyGenerator: (req) => req.headers['x-session-id'] || req.ip,
  message: 'Too many violation reports from this session'
});

module.exports = {
  generalLimiter,
  registrationLimiter,
  violationLimiter
};
