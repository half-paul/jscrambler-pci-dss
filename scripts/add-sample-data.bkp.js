/**
 * Add Sample Data to Database
 * Creates sample scripts and violations for testing the admin dashboard
 */

'use strict';

const { getDatabase } = require('../database-manager');

async function addSampleData() {
  console.log('========================================');
  console.log('Adding Sample Data to Database');
  console.log('========================================\n');

  const db = await getDatabase().initialize();

  try {
    // Sample Script 1: Approved jQuery
    console.log('[1/8] Adding approved jQuery script...');
    const script1 = await db.registerScript({
      url: 'https://code.jquery.com/jquery-3.6.0.min.js',
      contentHash: 'sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK',
      scriptType: 'external',
      sizeBytes: 89476,
      contentPreview: '/*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors...',
      pageUrl: 'http://localhost:3000/checkout.html',
      discoveryContext: JSON.stringify({ loadType: 'initial-load' })
    });
    console.log('  Script registered:', script1);

    if (!script1.scriptId) {
      throw new Error('Failed to get script ID from registration');
    }

    await db.approveScript(script1.scriptId, {
      approvedBy: 'admin',
      businessJustification: 'jQuery is required for DOM manipulation and AJAX functionality',
      scriptPurpose: 'Core JavaScript library for payment page interactions',
      scriptOwner: 'Frontend Team',
      riskLevel: 'low',
      approvalNotes: 'Approved - loaded from official jQuery CDN'
    });
    console.log('✓ jQuery approved');

    // Sample Script 2: Approved Bootstrap
    console.log('[2/8] Adding approved Bootstrap script...');
    const script2 = await db.registerScript({
      url: 'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js',
      contentHash: 'sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p',
      scriptType: 'external',
      sizeBytes: 78556,
      contentPreview: '/*! Bootstrap v5.1.3 (https://getbootstrap.com/)...',
      pageUrl: 'http://localhost:3000/checkout.html',
      discoveryContext: JSON.stringify({ loadType: 'initial-load' })
    });

    await db.approveScript(script2.scriptId, {
      approvedBy: 'admin',
      businessJustification: 'Bootstrap provides responsive UI components for payment forms',
      scriptPurpose: 'UI framework for responsive design',
      scriptOwner: 'Frontend Team',
      riskLevel: 'low',
      approvalNotes: 'Approved - loaded from trusted jsDelivr CDN'
    });
    console.log('✓ Bootstrap approved');

    // Sample Script 3: Pending Analytics
    console.log('[3/8] Adding pending analytics script...');
    await db.registerScript({
      url: 'https://analytics.example.com/tracker.js',
      contentHash: 'sha384-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz5678901234567890',
      scriptType: 'external',
      sizeBytes: 45678,
      contentPreview: '(function(){var analytics=window.analytics||[];analytics.track=function()...',
      pageUrl: 'http://localhost:3000/checkout.html',
      discoveryContext: JSON.stringify({ loadType: 'dynamic', addedBy: 'marketing-tag-manager' })
    });
    console.log('✓ Analytics script pending approval');

    // Sample Script 4: Pending Chat Widget
    console.log('[4/8] Adding pending chat widget...');
    await db.registerScript({
      url: 'https://widget.livechat.com/widget-v3.min.js',
      contentHash: 'sha384-xyz789abc012def345ghi678jkl901mno234pqr567stu890vwx123yz4567890123',
      scriptType: 'external',
      sizeBytes: 67890,
      contentPreview: '!function(e,t){var n=function(){...LiveChat widget initialization...',
      pageUrl: 'http://localhost:3000/support.html',
      discoveryContext: JSON.stringify({ loadType: 'dynamic', addedBy: 'support-team' })
    });
    console.log('✓ Chat widget pending approval');

    // Sample Script 5: Rejected Cryptocurrency Miner
    console.log('[5/8] Adding rejected mining script...');
    const script5 = await db.registerScript({
      url: 'https://suspicious-cdn.example.com/miner.js',
      contentHash: 'sha384-mal123ware456hash789012345678901234567890123456789012345678901234',
      scriptType: 'external',
      sizeBytes: 123456,
      contentPreview: 'var _0x4a2b=["miner","init","hashrate","submit"]; (function(){...',
      pageUrl: 'http://localhost:3000/payment.html',
      discoveryContext: JSON.stringify({ loadType: 'dynamic', addedBy: 'unknown-injection' })
    });

    await db.rejectScript(script5.scriptId, {
      rejectedBy: 'admin',
      rejectionReason: 'Unauthorized cryptocurrency mining script detected',
      notes: 'CRITICAL: Potential malware. Investigate injection source immediately.'
    });
    console.log('✓ Mining script rejected');

    // Sample Script 6: Inline Payment Handler (Approved)
    console.log('[6/8] Adding approved inline payment script...');
    const script6 = await db.registerScript({
      url: 'inline-script-payment-handler',
      contentHash: 'sha384-pay123ment456handler789012345678901234567890123456789012345678901',
      scriptType: 'inline',
      sizeBytes: 2345,
      contentPreview: 'function processPayment(cardData) { validateCard(cardData); submitToGateway...',
      pageUrl: 'http://localhost:3000/checkout.html',
      discoveryContext: JSON.stringify({ loadType: 'initial-load', position: 'script-tag-3' })
    });

    await db.approveScript(script6.scriptId, {
      approvedBy: 'admin',
      businessJustification: 'Core payment processing logic for PCI-compliant checkout',
      scriptPurpose: 'Handles payment card validation and submission',
      scriptOwner: 'Payment Team',
      riskLevel: 'high',
      approvalNotes: 'Approved after security review - critical payment functionality'
    });
    console.log('✓ Inline payment handler approved');

    // Sample Violation 1: Hash Mismatch - jQuery Updated
    console.log('[7/8] Adding hash mismatch violation...');
    await db.logViolation({
      scriptId: script1.scriptId,
      scriptUrl: 'https://code.jquery.com/jquery-3.6.0.min.js',
      oldHash: 'sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK',
      newHash: 'sha384-NEWWW3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfNEW',
      violationType: 'HASH_MISMATCH',
      pageUrl: 'http://localhost:3000/checkout.html',
      userSession: 'session-abc123',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0.4664.110',
      ipAddress: '192.168.1.100',
      severity: 'HIGH',
      actionTaken: 'REPORTED',
      loadType: 'initial-load'
    });
    console.log('✓ Hash mismatch violation logged');

    // Sample Violation 2: Unauthorized Script
    console.log('[8/8] Adding unauthorized script violation...');
    await db.logViolation({
      scriptId: null,
      scriptUrl: 'https://evil-tracker.com/tracking-pixel.js',
      oldHash: null,
      newHash: 'sha384-evil123track456pixel789012345678901234567890123456789012345678901',
      violationType: 'UNAUTHORIZED_SCRIPT',
      pageUrl: 'http://localhost:3000/payment.html',
      userSession: 'session-xyz789',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15',
      ipAddress: '10.0.0.50',
      severity: 'CRITICAL',
      actionTaken: 'REPORTED',
      loadType: 'dynamic',
      context: JSON.stringify({
        source: 'unknown',
        injectionMethod: 'document.createElement',
        timestamp: new Date().toISOString()
      })
    });
    console.log('✓ Unauthorized script violation logged');

    console.log('\n========================================');
    console.log('Sample Data Added Successfully!');
    console.log('========================================\n');

    // Show summary
    const compliance = await db.getComplianceSummary();
    const violations = await db.getViolationStatistics();

    console.log('Dashboard Summary:');
    console.log('------------------');
    console.log(`Total Scripts: ${compliance.total_scripts}`);
    console.log(`  ✓ Approved: ${compliance.approved_scripts}`);
    console.log(`  ⏳ Pending: ${compliance.pending_scripts}`);
    console.log(`  ✗ Rejected: ${compliance.rejected_scripts}`);
    console.log(`\nTotal Violations: ${violations.total_violations}`);
    console.log(`  🔴 Critical: ${violations.critical_count}`);
    console.log(`  🟠 High: ${violations.high_count}`);
    console.log(`  🟡 Medium: ${violations.medium_count}`);
    console.log(`  🟢 Low: ${violations.low_count}`);

    console.log('\n✓ You can now refresh the admin panel to see the data');
    console.log('  http://localhost:3000/admin-panel.html\n');

  } catch (error) {
    console.error('Error adding sample data:', error.message);
    throw error;
  } finally {
    await db.close();
  }
}

// Run the script
addSampleData().catch(console.error);
