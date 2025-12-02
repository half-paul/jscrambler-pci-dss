// Test script to verify violation cleanup on approval and deletion
const fetch = require('node-fetch');
const { DatabaseManager } = require('./database-manager');

const API_BASE = 'http://localhost:3000';
const API_TOKEN = 'demo-token-12345';

let db;

async function apiCall(endpoint, options = {}) {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'X-API-Token': API_TOKEN,
      'Content-Type': 'application/json',
      ...options.headers
    }
  });
  return response.json();
}

async function getViolationCount(scriptUrl) {
  const result = await db.queryOne(
    'SELECT COUNT(*) as count FROM integrity_violations WHERE script_url = ?',
    [scriptUrl]
  );
  return result.count;
}

async function test() {
  // Initialize database
  db = new DatabaseManager();
  await db.initialize();

  console.log('\n========================================');
  console.log('Testing Violation Cleanup');
  console.log('========================================\n');

  // Test 1: Single approval clears violations
  console.log('Test 1: Single Approval Violation Cleanup');
  console.log('-----------------------------------------');

  const scriptUrl1 = 'https://cdn.example.com/jquery-3.6.0.min.js';
  const beforeCount1 = await getViolationCount(scriptUrl1);
  console.log(`Before approval: ${beforeCount1} violations for ${scriptUrl1}`);

  if (beforeCount1 === 0) {
    console.log('⚠️  No violations to test. Run add-sample-data.js and add violations first.');
    return;
  }

  // Approve script ID 42
  const approveResult = await apiCall('/api/admin/scripts/42/approve', {
    method: 'POST',
    body: JSON.stringify({
      businessJustification: 'Test approval',
      scriptPurpose: 'Testing',
      scriptOwner: 'Test Team',
      riskLevel: 'low',
      approvalNotes: 'Testing violation cleanup'
    })
  });

  console.log(`Approval result:`, approveResult);

  const afterCount1 = await getViolationCount(scriptUrl1);
  console.log(`After approval: ${afterCount1} violations`);
  console.log(approveResult.violationsCleared > 0 ?
    `✅ SUCCESS: ${approveResult.violationsCleared} violations cleared` :
    '❌ FAIL: No violations cleared');

  // Test 2: Bulk approval clears violations
  console.log('\n Test 2: Bulk Approval Violation Cleanup');
  console.log('-----------------------------------------');

  const scriptUrl2 = 'https://cdn.example.com/payment-widget.js';
  const beforeCount2 = await getViolationCount(scriptUrl2);
  console.log(`Before bulk approval: ${beforeCount2} violations for ${scriptUrl2}`);

  if (beforeCount2 === 0) {
    console.log('⚠️  No violations for bulk test.');
  } else {
    // Bulk approve scripts 43 and 44
    const bulkResult = await apiCall('/api/admin/scripts/bulk-approve', {
      method: 'POST',
      body: JSON.stringify({
        scriptIds: [43, 44],
        businessJustification: 'Bulk test approval',
        scriptPurpose: 'Testing bulk operations',
        scriptOwner: 'Test Team',
        riskLevel: 'low',
        approvalNotes: 'Testing bulk violation cleanup'
      })
    });

    console.log(`Bulk approval result:`, bulkResult);

    const afterCount2 = await getViolationCount(scriptUrl2);
    console.log(`After bulk approval: ${afterCount2} violations`);
    console.log(bulkResult.violationsCleared > 0 ?
      `✅ SUCCESS: ${bulkResult.violationsCleared} violations cleared` :
      '❌ FAIL: No violations cleared');
  }

  console.log('\n========================================');
  console.log('Test Complete!');
  console.log('========================================\n');

  // Clean up
  await db.close();
}

test().catch(console.error);
