/**
 * Database Initialization Script
 * Initialize database and create default admin user
 */

'use strict';

require('dotenv').config();
const { getDatabase } = require('../database-manager');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

async function initDatabase() {
  console.log('========================================');
  console.log('Database Initialization');
  console.log('========================================\n');

  try {
    // Initialize database
    const db = getDatabase({
      type: process.env.DB_TYPE || 'sqlite',
      sqlitePath: process.env.SQLITE_PATH || './data/integrity-monitor.db',
      pgHost: process.env.PG_HOST,
      pgPort: process.env.PG_PORT,
      pgDatabase: process.env.PG_DATABASE,
      pgUser: process.env.PG_USER,
      pgPassword: process.env.PG_PASSWORD
    });

    await db.initialize();

    console.log('[Init] Creating default admin user...');

    // Generate secure password hash
    const defaultPassword = 'admin123'; // CHANGE THIS IN PRODUCTION
    const passwordHash = await bcrypt.hash(defaultPassword, 10);

    // Generate API token
    const apiToken = process.env.DEFAULT_ADMIN_TOKEN || crypto.randomBytes(32).toString('hex');

    // Insert or update admin user
    try {
      await db.query(
        `INSERT INTO admin_users (username, email, password_hash, api_token, role)
         VALUES (?, ?, ?, ?, ?)`,
        ['admin', 'admin@example.com', passwordHash, apiToken, 'admin']
      );
      console.log('[Init] Default admin user created');
    } catch (err) {
      if (err.message.includes('UNIQUE constraint')) {
        console.log('[Init] Admin user already exists, updating token...');
        await db.query(
          'UPDATE admin_users SET api_token = ? WHERE username = ?',
          [apiToken, 'admin']
        );
      } else {
        throw err;
      }
    }

    console.log('\n========================================');
    console.log('Initialization Complete!');
    console.log('========================================');
    console.log('\nDefault Admin Credentials:');
    console.log('  Username: admin');
    console.log('  Password: admin123');
    console.log('  API Token:', apiToken);
    console.log('\n⚠️  IMPORTANT: Change these credentials in production!');
    console.log('\nYou can now start the server:');
    console.log('  npm start');
    console.log('  npm run dev (for development)');
    console.log('\nAdmin Panel:');
    console.log(`  http://localhost:${process.env.PORT || 3000}/admin-panel.html`);
    console.log('========================================\n');

    await db.close();
    process.exit(0);

  } catch (error) {
    console.error('\n[Error] Initialization failed:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

initDatabase();
