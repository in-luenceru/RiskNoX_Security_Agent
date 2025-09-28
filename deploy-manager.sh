#!/bin/bash

#
# RiskNoX Manager Deployment Script
# Automated deployment for RiskNoX Security Manager with Docker Compose
#

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER_DIR="${SCRIPT_DIR}/manager"
ENV_FILE="${MANAGER_DIR}/.env.production"
DOCKER_COMPOSE_FILE="${MANAGER_DIR}/docker-compose.prod.yml"
BACKUP_DIR="/opt/risknox-backups"
LOG_FILE="/var/log/risknox-deploy.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $1${NC}" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] [WARN] $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $1${NC}" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] [SUCCESS] $1${NC}" | tee -a "$LOG_FILE"
}

# Help function
show_help() {
    cat << EOF
RiskNoX Manager Deployment Script

Usage: $0 [OPTIONS]

OPTIONS:
    --install           Fresh installation
    --update            Update existing installation
    --start             Start services
    --stop              Stop services
    --restart           Restart services
    --status            Show service status
    --logs              Show logs
    --backup            Create backup
    --restore FILE      Restore from backup
    --cleanup           Clean up old data
    --ssl-setup DOMAIN  Setup SSL certificates
    --help              Show this help

EXAMPLES:
    $0 --install                          # Fresh installation
    $0 --update                           # Update existing installation
    $0 --ssl-setup example.com            # Setup SSL for domain
    $0 --backup                           # Create backup
    $0 --restore /path/to/backup.tar.gz   # Restore from backup

EOF
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    local missing_deps=()
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        missing_deps+=("docker-compose")
    fi
    
    # Check required directories
    if [[ ! -d "$MANAGER_DIR" ]]; then
        error "Manager directory not found: $MANAGER_DIR"
        exit 1
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error "Missing dependencies: ${missing_deps[*]}"
        log "Please install the missing dependencies and try again"
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Setup environment
setup_environment() {
    log "Setting up environment..."
    
    # Create necessary directories
    mkdir -p "$BACKUP_DIR"
    mkdir -p "${MANAGER_DIR}/logs"
    mkdir -p "${MANAGER_DIR}/uploads"
    mkdir -p "${MANAGER_DIR}/nginx/ssl"
    
    # Set up log file
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    # Create environment file if it doesn't exist
    if [[ ! -f "$ENV_FILE" ]]; then
        log "Creating production environment file..."
        cp "${MANAGER_DIR}/.env.example" "$ENV_FILE"
        
        # Generate secure passwords
        POSTGRES_PASSWORD=$(openssl rand -base64 32)
        JWT_SECRET=$(openssl rand -base64 64)
        S3_ACCESS_KEY=$(openssl rand -hex 16)
        S3_SECRET_KEY=$(openssl rand -base64 32)
        ADMIN_PASSWORD=$(openssl rand -base64 16)
        GRAFANA_PASSWORD=$(openssl rand -base64 16)
        
        # Update environment file with generated passwords
        sed -i "s/CHANGE_THIS_PASSWORD_IN_PRODUCTION/$POSTGRES_PASSWORD/g" "$ENV_FILE"
        sed -i "s/CHANGE_THIS_JWT_SECRET_IN_PRODUCTION/$JWT_SECRET/g" "$ENV_FILE"
        sed -i "s/CHANGE_THIS_ACCESS_KEY/$S3_ACCESS_KEY/g" "$ENV_FILE"
        sed -i "s/CHANGE_THIS_SECRET_KEY_IN_PRODUCTION/$S3_SECRET_KEY/g" "$ENV_FILE"
        sed -i "s/CHANGE_THIS_ADMIN_PASSWORD/$ADMIN_PASSWORD/g" "$ENV_FILE"
        sed -i "s/CHANGE_THIS_GRAFANA_PASSWORD/$GRAFANA_PASSWORD/g" "$ENV_FILE"
        
        success "Environment file created with secure passwords"
        log "Admin password: $ADMIN_PASSWORD"
        log "Please save these credentials securely!"
    fi
    
    success "Environment setup completed"
}

# Install manager
install_manager() {
    log "Installing RiskNoX Manager..."
    
    cd "$MANAGER_DIR"
    
    # Build and start services
    log "Building Docker images..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" build
    
    log "Starting services..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" up -d
    
    # Wait for services to be ready
    log "Waiting for services to initialize..."
    sleep 30
    
    # Run database migrations
    log "Running database migrations..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" exec -T manager alembic upgrade head
    
    # Create MinIO bucket
    log "Setting up MinIO bucket..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" exec -T minio mc alias set local http://localhost:9000 \
        "$(grep S3_ACCESS_KEY "$ENV_FILE" | cut -d'=' -f2)" \
        "$(grep S3_SECRET_KEY "$ENV_FILE" | cut -d'=' -f2)"
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" exec -T minio mc mb local/risknox-storage --ignore-existing
    
    success "RiskNoX Manager installation completed"
}

# Update manager
update_manager() {
    log "Updating RiskNoX Manager..."
    
    cd "$MANAGER_DIR"
    
    # Create backup before update
    create_backup
    
    # Pull latest images
    log "Pulling latest Docker images..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" pull
    
    # Rebuild and restart services
    log "Rebuilding services..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" build --no-cache
    
    log "Restarting services..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" up -d
    
    # Run any new migrations
    log "Running database migrations..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" exec -T manager alembic upgrade head
    
    success "RiskNoX Manager update completed"
}

# Start services
start_services() {
    log "Starting RiskNoX Manager services..."
    
    cd "$MANAGER_DIR"
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" up -d
    
    success "Services started"
}

# Stop services
stop_services() {
    log "Stopping RiskNoX Manager services..."
    
    cd "$MANAGER_DIR"
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" down
    
    success "Services stopped"
}

# Restart services
restart_services() {
    log "Restarting RiskNoX Manager services..."
    
    stop_services
    sleep 5
    start_services
    
    success "Services restarted"
}

# Show service status
show_status() {
    log "Checking service status..."
    
    cd "$MANAGER_DIR"
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" ps
    
    echo ""
    log "Service health checks:"
    
    # Check manager health
    if curl -f -s http://localhost:8001/health > /dev/null; then
        success "✓ Manager API: Healthy"
    else
        error "✗ Manager API: Unhealthy"
    fi
    
    # Check admin UI
    if curl -f -s http://localhost:8080 > /dev/null; then
        success "✓ Admin UI: Accessible"
    else
        error "✗ Admin UI: Not accessible"
    fi
    
    # Check Prometheus
    if curl -f -s http://localhost:9090 > /dev/null; then
        success "✓ Prometheus: Running"
    else
        warn "✗ Prometheus: Not accessible"
    fi
    
    # Check Grafana
    if curl -f -s http://localhost:3000 > /dev/null; then
        success "✓ Grafana: Running"
    else
        warn "✗ Grafana: Not accessible"
    fi
}

# Show logs
show_logs() {
    log "Showing recent logs..."
    
    cd "$MANAGER_DIR"
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" logs --tail=100 -f
}

# Create backup
create_backup() {
    log "Creating backup..."
    
    BACKUP_NAME="risknox-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    BACKUP_PATH="$BACKUP_DIR/$BACKUP_NAME"
    
    cd "$MANAGER_DIR"
    
    # Create database dump
    log "Creating database backup..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" exec -T postgres pg_dump -U "$(grep POSTGRES_USER "$ENV_FILE" | cut -d'=' -f2)" "$(grep POSTGRES_DB "$ENV_FILE" | cut -d'=' -f2)" > db_backup.sql
    
    # Create full backup
    log "Creating full system backup..."
    tar -czf "$BACKUP_PATH" \
        --exclude='./logs/*' \
        --exclude='./uploads/*' \
        --exclude='./.env*' \
        .
    
    # Clean up database dump
    rm -f db_backup.sql
    
    success "Backup created: $BACKUP_PATH"
}

# Restore from backup
restore_backup() {
    local backup_file="$1"
    
    if [[ ! -f "$backup_file" ]]; then
        error "Backup file not found: $backup_file"
        exit 1
    fi
    
    log "Restoring from backup: $backup_file"
    
    # Stop services
    stop_services
    
    # Create restoration directory
    RESTORE_DIR="/tmp/risknox-restore-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$RESTORE_DIR"
    
    # Extract backup
    tar -xzf "$backup_file" -C "$RESTORE_DIR"
    
    # Restore files
    cd "$MANAGER_DIR"
    cp -r "$RESTORE_DIR"/* .
    
    # Start services
    start_services
    
    # Wait for database
    sleep 20
    
    # Restore database if backup exists
    if [[ -f "$RESTORE_DIR/db_backup.sql" ]]; then
        log "Restoring database..."
        docker-compose -f "$DOCKER_COMPOSE_FILE" --env-file "$ENV_FILE" exec -T postgres psql -U "$(grep POSTGRES_USER "$ENV_FILE" | cut -d'=' -f2)" "$(grep POSTGRES_DB "$ENV_FILE" | cut -d'=' -f2)" < "$RESTORE_DIR/db_backup.sql"
    fi
    
    # Clean up
    rm -rf "$RESTORE_DIR"
    
    success "Restore completed"
}

# Cleanup old data
cleanup() {
    log "Cleaning up old data..."
    
    cd "$MANAGER_DIR"
    
    # Clean up old Docker images
    docker image prune -f
    
    # Clean up old backups (keep last 10)
    find "$BACKUP_DIR" -name "risknox-backup-*.tar.gz" -type f | sort -r | tail -n +11 | xargs -r rm -f
    
    # Clean up old logs (keep last 7 days)
    find "${MANAGER_DIR}/logs" -name "*.log" -type f -mtime +7 -delete
    
    success "Cleanup completed"
}

# Setup SSL certificates
setup_ssl() {
    local domain="$1"
    
    if [[ -z "$domain" ]]; then
        error "Domain name is required for SSL setup"
        exit 1
    fi
    
    log "Setting up SSL for domain: $domain"
    
    # Install certbot if not available
    if ! command -v certbot &> /dev/null; then
        log "Installing certbot..."
        apt-get update && apt-get install -y certbot
    fi
    
    # Generate certificate
    log "Generating SSL certificate..."
    certbot certonly --standalone -d "$domain" --non-interactive --agree-tos --email admin@"$domain"
    
    # Copy certificates to nginx directory
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "${MANAGER_DIR}/nginx/ssl/cert.pem"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "${MANAGER_DIR}/nginx/ssl/key.pem"
    
    # Update nginx configuration for SSL
    sed -i 's/# return 301 https/return 301 https/' "${MANAGER_DIR}/nginx/nginx.conf"
    sed -i 's/# server {/server {/' "${MANAGER_DIR}/nginx/nginx.conf"
    sed -i "s/your-domain.com/$domain/" "${MANAGER_DIR}/nginx/nginx.conf"
    
    # Restart services
    restart_services
    
    success "SSL setup completed for $domain"
}

# Show deployment summary
show_summary() {
    cat << EOF

╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        RiskNoX Manager Deployment Complete                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

SERVICES RUNNING:
✓ Manager API:     http://localhost:8001
✓ Admin UI:        http://localhost:8080  
✓ Database:        PostgreSQL on port 5432
✓ Redis:           Redis on port 6379
✓ Storage:         MinIO on port 9000
✓ Monitoring:      Prometheus (9090), Grafana (3000)

MANAGEMENT COMMANDS:
   Status:    $0 --status
   Logs:      $0 --logs
   Restart:   $0 --restart
   Backup:    $0 --backup

NEXT STEPS:
1. Access the web interface at http://localhost:8080
2. Deploy agents using the Install-RiskNoXAgent.ps1 script
3. Configure monitoring dashboards in Grafana
4. Set up regular backups with cron

For SSL setup: $0 --ssl-setup your-domain.com

EOF
}

# Main function
main() {
    case "${1:-}" in
        --install)
            check_prerequisites
            setup_environment
            install_manager
            show_summary
            ;;
        --update)
            check_prerequisites
            update_manager
            ;;
        --start)
            start_services
            ;;
        --stop)
            stop_services
            ;;
        --restart)
            restart_services
            ;;
        --status)
            show_status
            ;;
        --logs)
            show_logs
            ;;
        --backup)
            create_backup
            ;;
        --restore)
            restore_backup "$2"
            ;;
        --cleanup)
            cleanup
            ;;
        --ssl-setup)
            setup_ssl "$2"
            ;;
        --help)
            show_help
            ;;
        *)
            error "Unknown option: ${1:-}"
            show_help
            exit 1
            ;;
    esac
}

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Run main function
main "$@"