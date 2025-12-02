// Test script to verify audit trail API is working
const fetch = require('node-fetch');
const { DatabaseManager } = require('./database-manager');

const API_BASE = 'http://localhost:3000';
const API_TOKEN = 'demo-token-12345';

async function testAuditAPI() {
  console.log('\n========================================');
  console.log('Testing Audit Trail API');
  console.log('========================================\n');

  // Step 1: Add test data directly to database while server is running
  console.log('Step 1: Adding test audit trail data...');
  const db = new DatabaseManager();
  await db.initialize();

  const testEntries = [
    {
      username: 'admin',
      action_type: 'script_approved',
      action_description: 'Test approval action',
      entity_type: 'script',
      entity_id: '100',
      action_reason: 'Testing audit trail display',
      success: 1,
      timestamp: new Date().toISOString()
    },
    {
      username: 'admin',
      action_type: 'script_rejected',
      action_description: 'Test rejection action',
      entity_type: 'script',
      entity_id: '101',
      action_reason: 'Testing rejection display',
      success: 1,
      timestamp: new Date(Date.now() - 86400000).toISOString() // 1 day ago
    }
  ];

  for (const entry of testEntries) {
    await db.query(
      `INSERT INTO audit_trail
       (username, action_type, action_description, entity_type, entity_id, action_reason, error_message, success, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        entry.username,
        entry.action_type,
        entry.action_description,
        entry.entity_type,
        entry.entity_id,
        entry.action_reason,
        null,
        entry.success,
        entry.timestamp
      ]
    );
  }

  await db.close();
  console.log(`✓ Added ${testEntries.length} test entries\n`);

  // Step 2: Test the audit trail API endpoint
  console.log('Step 2: Testing GET /api/admin/audit-trail...');
  const response = await fetch(`${API_BASE}/api/admin/audit-trail?limit=10`, {
    headers: {
      'X-API-Token': API_TOKEN
    }
  });

  const data = await response.json();

  if (response.ok) {
    console.log('✅ API Response successful');
    console.log(`   Total logs: ${data.total}`);
    console.log(`   Logs returned: ${data.logs.length}`);
    console.log(`   Page: ${data.page}/${data.totalPages}`);

    if (data.logs.length > 0) {
      console.log('\n   Sample log entry:');
      const log = data.logs[0];
      console.log(`   - ID: ${log.id}`);
      console.log(`   - Username: ${log.username}`);
      console.log(`   - Action: ${log.action_type}`);
      console.log(`   - Description: ${log.action_description}`);
      console.log(`   - Timestamp: ${log.timestamp}`);
    }
  } else {
    console.log('❌ API Error:', data);
  }

  // Step 3: Test the stats endpoint
  console.log('\nStep 3: Testing GET /api/admin/audit-trail/stats...');
  const statsResponse = await fetch(`${API_BASE}/api/admin/audit-trail/stats`, {
    headers: {
      'X-API-Token': API_TOKEN
    }
  });

  const stats = await statsResponse.json();

  if (statsResponse.ok) {
    console.log('✅ Stats API Response successful');
    console.log(`   Total logs: ${stats.totalLogs}`);
    console.log(`   Last 24 hours: ${stats.last24Hours}`);
    console.log(`   Last 7 days: ${stats.last7Days}`);
    console.log(`   Failed actions: ${stats.failedActions}`);
  } else {
    console.log('❌ Stats API Error:', stats);
  }

  console.log('\n========================================');
  console.log('Audit Trail API Test Complete!');
  console.log('========================================\n');
}

testAuditAPI().catch(console.error);
