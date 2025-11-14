/**
 * MFA (Multi-Factor Authentication) Module
 * Handles username/password + TOTP authentication
 */

const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'default-jwt-secret-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

/**
 * Generate JWT tokens for authenticated session
 */
function generateTokens(payloadData) {
  const isTemp = payloadData.temp === true;

  let payload;
  let expiresIn = JWT_EXPIRES_IN;

  if (isTemp) {
    payload = { id: payloadData.id, temp: true };
    expiresIn = '5m'; // 5 minutes for temporary token
  } else {
    payload = {
      id: payloadData.id,
      username: payloadData.username,
      email: payloadData.email,
      role: payloadData.role
    };
  }

  const accessToken = jwt.sign(payload, JWT_SECRET, {
    expiresIn: expiresIn,
    issuer: 'script-integrity-monitor'
  });

  if (isTemp) {
    return { accessToken };
  }

  const refreshToken = jwt.sign(
    { id: payloadData.id, type: 'refresh' },
    JWT_SECRET,
    { expiresIn: JWT_REFRESH_EXPIRES_IN, issuer: 'script-integrity-monitor' }
  );

  return { accessToken, refreshToken };
}

/**
 * Verify JWT token
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET, { issuer: 'script-integrity-monitor' });
  } catch (error) {
    throw new Error('Invalid or expired token');
  }
}

/**
 * Generate MFA secret and QR code
 */
async function generateMFASecret(username) {
  const secret = speakeasy.generateSecret({
    name: `Script Integrity Monitor (${username})`,
    issuer: 'Script Integrity Monitor',
    length: 32
  });

  // Generate QR code as data URL
  const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

  return {
    secret: secret.base32,
    qrCode: qrCodeDataUrl,
    otpauthUrl: secret.otpauth_url
  };
}

/**
 * Verify TOTP token
 */
function verifyTOTP(secret, token) {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 2  // Allow 2 steps (60 seconds) of time drift
  });
}

/**
 * Generate backup codes
 */
function generateBackupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    // Generate 8-digit code
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    codes.push(code);
  }
  return codes;
}

/**
 * Hash backup code for storage
 */
function hashBackupCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

/**
 * Verify backup code
 */
function verifyBackupCode(hashedCode, inputCode) {
  const inputHash = hashBackupCode(inputCode);
  return hashedCode === inputHash;
}

/**
 * Calculate token expiry date
 */
function calculateExpiryDate(expiresIn) {
  const match = expiresIn.match(/^(\d+)([hdm])$/);
  if (!match) return new Date(Date.now() + 3600000); // Default 1 hour

  const value = parseInt(match[1]);
  const unit = match[2];

  const multipliers = {
    'm': 60 * 1000,           // minutes
    'h': 60 * 60 * 1000,      // hours
    'd': 24 * 60 * 60 * 1000  // days
  };

  return new Date(Date.now() + (value * multipliers[unit]));
}

module.exports = {
  generateTokens,
  verifyToken,
  generateMFASecret,
  verifyTOTP,
  generateBackupCodes,
  hashBackupCode,
  verifyBackupCode,
  calculateExpiryDate
};
