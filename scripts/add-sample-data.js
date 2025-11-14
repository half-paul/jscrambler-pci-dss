/**
 * Add Sample Script Data for Testing
 */

'use strict';

require('dotenv').config();
const { getDatabase } = require('../database-manager');

async function addSampleData() {
  console.log('Adding sample script data...\n');

  try {
    const db = getDatabase({
      type: process.env.DB_TYPE || 'sqlite',
      sqlitePath: process.env.SQLITE_PATH || './data/integrity-monitor.db'
    });

    await db.initialize();

    // Sample scripts
    const scripts = [
      {
        url: 'https://cdn.example.com/jquery-3.6.0.min.js',
        content_hash: 'sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK',
        script_type: 'external',
        page_url: 'https://example.com/checkout',
        status: 'pending_approval',
        size_bytes: 89476
      },
      {
        url: 'https://cdn.example.com/payment-widget.js',
        content_hash: 'sha384-AbCdEf1234567890aBcDeF1234567890AbCdEf1234567890aBcDeF1234567890',
        script_type: 'external',
        page_url: 'https://example.com/checkout',
        status: 'pending_approval',
        size_bytes: 45328
      },
      {
        url: 'inline-script-0',
        content_hash: 'sha384-InLiNe12345ScRiPtHaSh67890AbCdEf1234567890aBcDeF1234567890aBcDeF',
        script_type: 'inline',
        page_url: 'https://example.com/checkout',
        status: 'pending_approval',
        script_position: 0,
        content_preview: 'console.log("Payment form initialized");',
        size_bytes: 256
      },
      {
        url: 'https://cdn.example.com/analytics.js',
        content_hash: 'sha384-aNaLyTiCs1234567890AbCdEf1234567890aBcDeF1234567890aBcDeF12345678',
        script_type: 'external',
        page_url: 'https://example.com/checkout',
        status: 'approved',
        business_justification: 'Required for tracking checkout conversions',
        script_purpose: 'Analytics and conversion tracking',
        script_owner: 'Marketing Team',
        risk_level: 'low',
        approval_notes: 'Approved for production use',
        approved_by: 'admin',
        size_bytes: 67234
      },
      {
        url: 'https://cdn.example.com/payment-processor.js',
        content_hash: 'sha384-PaYmEnT1234567890AbCdEf1234567890aBcDeF1234567890aBcDeF1234567890',
        script_type: 'external',
        page_url: 'https://example.com/checkout',
        status: 'approved',
        business_justification: 'Third-party payment processor integration',
        script_purpose: 'Payment processing',
        script_owner: 'Engineering Team',
        risk_level: 'high',
        approval_notes: 'Verified with security team - using official CDN',
        approved_by: 'admin',
        size_bytes: 123456
      }
    ];

    console.log('Inserting sample scripts...');
    for (const script of scripts) {
      try {
        await db.query(
          `INSERT INTO scripts (
            url, content_hash, script_type, page_url, status,
            size_bytes, script_position, content_preview,
            business_justification, script_purpose, script_owner,
            risk_level, approval_notes, approved_by, approved_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ${script.status === 'approved' ? 'CURRENT_TIMESTAMP' : 'NULL'})`,
          [
            script.url,
            script.content_hash,
            script.script_type,
            script.page_url,
            script.status,
            script.size_bytes,
            script.script_position || null,
            script.content_preview || null,
            script.business_justification || null,
            script.script_purpose || null,
            script.script_owner || null,
            script.risk_level || null,
            script.approval_notes || null,
            script.approved_by || null
          ]
        );
        console.log(`  ✓ Added: ${script.url} (${script.status})`);
      } catch (err) {
        if (err.message.includes('UNIQUE')) {
          console.log(`  - Skipped (exists): ${script.url}`);
        } else {
          throw err;
        }
      }
    }

    console.log('\n✓ Sample data added successfully!');
    console.log('\nYou can now view the scripts in the admin panel:');
    console.log('  http://localhost:3000/admin-panel.html');
    console.log('\n  - Pending Approvals tab: 3 scripts');
    console.log('  - Script Inventory tab: 5 scripts');

    await db.close();
    process.exit(0);

  } catch (error) {
    console.error('\n✗ Error adding sample data:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

addSampleData();
