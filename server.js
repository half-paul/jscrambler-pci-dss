/**
 * Script Integrity Monitor Server Entry Point
 * PCI DSS v4.0 Requirement 6.4.3 Compliance
 *
 * This file initializes and starts the modular Express application
 * with database integration and alert scheduling.
 *
 * @version 2.0.0 - Modular Architecture
 */

'use strict';

require('dotenv').config();
const { createApp } = require('./src/server/app');

const PORT = process.env.PORT || 3000;

/**
 * Start the server
 */
async function startServer() {
  try {
    // Create and initialize the Express app
    const { app, db, alertScheduler } = await createApp();

    // Start alert scheduler
    await alertScheduler.start();

    // Start Express server
    app.listen(PORT, () => {
      console.log('\n========================================');
      console.log('Script Integrity Monitor Server');
      console.log('========================================');
      console.log(`Server running on port ${PORT}`);
      console.log(`Database: ${db.config.type}`);
      console.log('\nPublic API Endpoints:');
      console.log(`  POST   http://localhost:${PORT}/api/scripts/register`);
      console.log(`  GET    http://localhost:${PORT}/api/scripts/status/:hash`);
      console.log(`  POST   http://localhost:${PORT}/api/scripts/violation`);
      console.log(`  POST   http://localhost:${PORT}/api/headers/register`);
      console.log(`  POST   http://localhost:${PORT}/api/headers/violation`);
      console.log(`  POST   http://localhost:${PORT}/api/network/violation`);
      console.log('\nAdmin API Endpoints (require authentication):');
      console.log(`  POST   http://localhost:${PORT}/api/admin/auth/login`);
      console.log(`  GET    http://localhost:${PORT}/api/admin/scripts/pending`);
      console.log(`  POST   http://localhost:${PORT}/api/admin/scripts/:id/approve`);
      console.log(`  POST   http://localhost:${PORT}/api/admin/scripts/:id/reject`);
      console.log(`  GET    http://localhost:${PORT}/api/admin/violations`);
      console.log(`  GET    http://localhost:${PORT}/api/admin/dashboard`);
      console.log(`  GET    http://localhost:${PORT}/api/admin/pci-dss/summary`);
      console.log(`  GET    http://localhost:${PORT}/api/admin/audit-trail`);
      console.log('\nAdmin Panel:');
      console.log(`  http://localhost:${PORT}/admin-panel.html`);
      console.log('\nHealth Check:');
      console.log(`  GET    http://localhost:${PORT}/health`);
      console.log('========================================\n');
    });

    // Store references for graceful shutdown
    global.db = db;

  } catch (error) {
    console.error('Failed to start server:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

/**
 * Graceful shutdown handler
 */
async function gracefulShutdown(signal) {
  console.log(`\n[Server] Received ${signal}, shutting down gracefully...`);

  try {
    if (global.db) {
      await global.db.close();
      console.log('[Server] Database connection closed');
    }

    console.log('[Server] Shutdown complete');
    process.exit(0);
  } catch (error) {
    console.error('[Server] Error during shutdown:', error.message);
    process.exit(1);
  }
}

// Register shutdown handlers
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  console.error('[Server] Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[Server] Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start the server
startServer();
