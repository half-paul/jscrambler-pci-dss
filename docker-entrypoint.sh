#!/bin/sh
set -e

# Wait for PostgreSQL to be ready (if using PostgreSQL)
if [ "$DB_TYPE" = "postgres" ]; then
  echo "Waiting for PostgreSQL to be ready..."
  node wait-for-postgres.js || exit 1
  
  # Initialize database and create admin user
  echo "Initializing PostgreSQL database..."
  npm run db:init || echo "Database initialization completed or skipped"
elif [ "$DB_TYPE" = "sqlite" ] || [ -z "$DB_TYPE" ]; then
  DB_PATH="${SQLITE_PATH:-/app/data/integrity-monitor.db}"
  if [ ! -f "$DB_PATH" ]; then
    echo "Database not found. Initializing SQLite database..."
    npm run db:init
    echo "Database initialized successfully."
  else
    echo "SQLite database already exists at $DB_PATH"
  fi
fi

# Start the application
echo "Starting server..."
exec npm start

