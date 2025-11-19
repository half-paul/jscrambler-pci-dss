# Docker Deployment Guide

This guide explains how to run the Script Integrity Monitor in Docker containers.

## Quick Start

### Option 1: Using Docker Compose (Recommended)

The setup uses **PostgreSQL by default** in a separate container.

1. **Create environment file** (optional, uses defaults if not provided):
   ```bash
   # Optional: Create .env file to customize settings
   # Default PostgreSQL credentials: postgres/postgres
   ```

2. **Build and start the containers**:
   ```bash
   docker-compose up -d
   ```

   This will start:
   - PostgreSQL container (`script-integrity-postgres`)
   - Application container (`script-integrity-monitor`)

3. **View logs**:
   ```bash
   docker-compose logs -f
   ```

4. **Access the application**:
   - Admin Panel: http://localhost:3000/admin-panel.html
   - Health Check: http://localhost:3000/health
   - API: http://localhost:3000/api

5. **Stop the container**:
   ```bash
   docker-compose down
   ```

### Option 2: Using Docker directly

1. **Build the image**:
   ```bash
   docker build -t script-integrity-monitor .
   ```

2. **Run the container**:
   ```bash
   docker run -d \
     --name script-integrity-monitor \
     -p 3000:3000 \
     -v $(pwd)/data:/app/data \
     -e DEFAULT_ADMIN_TOKEN=demo-token-12345 \
     script-integrity-monitor
   ```

3. **View logs**:
   ```bash
   docker logs -f script-integrity-monitor
   ```

## Configuration

### Environment Variables

The application can be configured using environment variables. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `NODE_ENV` | `production` | Node environment |
| `DB_TYPE` | `sqlite` | Database type (`sqlite` or `postgres`) |
| `SQLITE_PATH` | `/app/data/integrity-monitor.db` | SQLite database path |
| `DEFAULT_ADMIN_TOKEN` | `demo-token-12345` | Default admin API token |
| `CORS_ORIGIN` | `*` | CORS allowed origins |
| `IP_SALT` | `change-in-production` | Salt for IP hashing |
| `JWT_SECRET` | `change-in-production` | JWT secret key |

**⚠️ IMPORTANT:** Change default values in production!

### Using PostgreSQL

The Docker setup is **configured to use PostgreSQL by default**. PostgreSQL runs in a separate container.

**Default Configuration:**
- PostgreSQL service: `postgres` (PostgreSQL 15 Alpine)
- Database: `script_integrity`
- User: `postgres`
- Password: `postgres` (⚠️ Change in production!)

**To customize PostgreSQL settings**, set environment variables:

```bash
# Create or edit .env file
PG_DATABASE=script_integrity
PG_USER=postgres
PG_PASSWORD=your-secure-password
```

Then start services:
```bash
docker-compose up -d
```

The application container will:
1. Wait for PostgreSQL to be healthy (using `depends_on` with health check)
2. Wait for PostgreSQL to accept connections (using wait script)
3. Initialize the database schema
4. Create the default admin user
5. Start the application server

**To switch back to SQLite**, modify `docker-compose.yml`:
- Change `DB_TYPE=postgres` to `DB_TYPE=sqlite`
- Remove or comment out the `postgres` service
- Add back the SQLite volume mount: `- ./data:/app/data`

## Data Persistence

The database is persisted using Docker volumes:

- **PostgreSQL (default)**: Data is stored in a named Docker volume `postgres-data`
- **SQLite (if configured)**: Data is stored in `./data` directory (mounted as volume)

### PostgreSQL Backup

To backup PostgreSQL database:
```bash
docker-compose exec postgres pg_dump -U postgres script_integrity > backup.sql
```

To restore:
```bash
docker-compose exec -T postgres psql -U postgres script_integrity < backup.sql
```

### SQLite Backup (if using SQLite)

To backup SQLite database:
```bash
docker cp script-integrity-monitor:/app/data/integrity-monitor.db ./backup.db
```

To restore:
```bash
docker cp ./backup.db script-integrity-monitor:/app/data/integrity-monitor.db
```

## Health Checks

The container includes a health check that monitors the `/health` endpoint:

```bash
# Check container health
docker ps

# View health check status
docker inspect script-integrity-monitor | grep -A 10 Health
```

## Troubleshooting

### Container won't start

1. **Check logs**:
   ```bash
   docker-compose logs app
   ```

2. **Check database initialization**:
   ```bash
   docker-compose exec app ls -la /app/data
   ```

3. **Manually initialize database**:
   ```bash
   docker-compose exec app npm run db:init
   ```

### Database connection issues

1. **For SQLite**: Check volume mount permissions
   ```bash
   docker-compose exec app ls -la /app/data
   ```

2. **For PostgreSQL**: Check if PostgreSQL container is running
   ```bash
   docker-compose ps
   docker-compose logs postgres
   ```

### Database initialization errors

If you see PostgreSQL errors during database initialization (related to triggers, syntax errors):

1. **The database-manager.js has been updated** to automatically handle PostgreSQL-specific syntax:
   - Converts `INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL PRIMARY KEY`
   - Converts `DATETIME` → `TIMESTAMP`
   - Converts `INSERT OR IGNORE` → `INSERT ... ON CONFLICT DO NOTHING`
   - Converts SQLite triggers to PostgreSQL trigger functions

2. **If initialization still fails**, check logs for specific errors:
   ```bash
   docker-compose logs app | grep -A 5 "Migration failed"
   ```

3. **Common issues**:
   - **Trigger syntax errors**: Fixed in database-manager.js v2.0.0+
   - **"relation already exists"**: These are warnings, not errors - initialization continues
   - **Connection timeout**: PostgreSQL may need more time to start, increase `start_period` in health check

4. **Force re-initialization** (⚠️ deletes all data):
   ```bash
   # Drop database and recreate
   docker-compose down -v
   docker-compose up -d
   ```

### Port already in use

Change the port mapping in `docker-compose.yml`:
```yaml
ports:
  - "3001:3000"  # Use port 3001 on host
```

### Reset everything

```bash
# Stop and remove containers
docker-compose down

# Remove volumes (⚠️ deletes database)
docker-compose down -v

# Rebuild and start
docker-compose up -d --build
```

## Production Deployment

### Security Checklist

- [ ] Change `DEFAULT_ADMIN_TOKEN` to a secure random value
- [ ] Change `JWT_SECRET` to a secure random value
- [ ] Change `IP_SALT` to a secure random value
- [ ] Set `CORS_ORIGIN` to specific domains (not `*`)
- [ ] Use PostgreSQL for production (not SQLite)
- [ ] Set up SSL/TLS (use reverse proxy like nginx)
- [ ] Configure firewall rules
- [ ] Set up regular database backups
- [ ] Use secrets management (Docker secrets, Kubernetes secrets, etc.)

### Using Docker Secrets

For production, use Docker secrets instead of environment variables:

```yaml
services:
  app:
    secrets:
      - jwt_secret
      - admin_token
    environment:
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
      - DEFAULT_ADMIN_TOKEN_FILE=/run/secrets/admin_token

secrets:
  jwt_secret:
    external: true
  admin_token:
    external: true
```

### Reverse Proxy Setup

Example nginx configuration:

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Development

### Development Mode

For development with hot-reload:

```bash
# Override command in docker-compose.yml
docker-compose run --rm -e NODE_ENV=development app npm run dev
```

Or modify `docker-compose.yml`:

```yaml
services:
  app:
    command: npm run dev
    environment:
      - NODE_ENV=development
```

### Accessing Container Shell

```bash
docker-compose exec app sh
```

### Running Database Scripts

```bash
# Initialize database
docker-compose exec app npm run db:init

# Add sample data (if script exists)
docker-compose exec app npm run db:seed
```

## Monitoring

### View Logs

```bash
# All logs
docker-compose logs -f

# Specific service
docker-compose logs -f app

# Last 100 lines
docker-compose logs --tail=100 app
```

### Resource Usage

```bash
docker stats script-integrity-monitor
```

## Updates

### Update Application

```bash
# Pull latest code
git pull

# Rebuild and restart
docker-compose up -d --build
```

### Update Dependencies

```bash
# Rebuild with no cache
docker-compose build --no-cache

# Restart
docker-compose up -d
```

## Support

For issues or questions:
- Check application logs: `docker-compose logs app`
- Check container status: `docker-compose ps`
- Review this documentation
- Check main README.md for application-specific issues

