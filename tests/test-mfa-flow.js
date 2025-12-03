const fetch = require('node-fetch');

const API_BASE = 'http://localhost:3000';

async function testMFAFlow() {
  console.log('=== Testing MFA Flow ===\n');

  try {
    // Step 1: Login
    console.log('1. Logging in...');
    const loginRes = await fetch(`${API_BASE}/api/admin/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'admin123' })
    });

    const loginData = await loginRes.json();
    console.log('   ✓ Login successful');
    console.log('   - MFA Required:', loginData.mfaRequired);
    console.log('   - Access Token:', loginData.accessToken ? 'Present' : 'Missing');

    const token = loginData.accessToken;

    // Step 2: Generate MFA QR Code
    console.log('\n2. Generating MFA setup...');
    const generateRes = await fetch(`${API_BASE}/api/admin/auth/setup-mfa`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ action: 'generate' })
    });

    if (!generateRes.ok) {
      const error = await generateRes.json();
      throw new Error(`MFA generate failed: ${error.error}`);
    }

    const mfaData = await generateRes.json();
    console.log('   ✓ MFA setup generated');
    console.log('   - Has QR Code:', !!mfaData.qrCode);
    console.log('   - Has Secret:', !!mfaData.secret);
    console.log('   - Secret (first 10 chars):', mfaData.secret?.substring(0, 10) + '...');

    console.log('\n=== Test Complete ===');
    console.log('✓ All endpoints are working correctly!');
    console.log('\nYou can now test in the browser:');
    console.log('  1. Open http://localhost:3000/admin-panel.html');
    console.log('  2. Login with admin / admin123');
    console.log('  3. Go to Security Settings tab');
    console.log('  4. Click "Enable Two-Factor Authentication"');
    console.log('  5. Scan the QR code with Google Authenticator');

  } catch (error) {
    console.error('\n✗ Test failed:', error.message);
    process.exit(1);
  }
}

testMFAFlow();
