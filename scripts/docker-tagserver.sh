#!/bin/bash
# =============================================================================
# Docker Tag Server Management Script (Complete Integrated Version)
# =============================================================================
#
# PURPOSE:
#   Comprehensive CLI for managing GTM containers with Nginx reverse proxy,
#   SSL support, multi-domain routing, and container lifecycle management.
#
# FEATURES:
#   ✅ Container lifecycle (run, stop, start, restart, delete)
#   ✅ Multi-domain/subdomain support with Nginx reverse proxy
#   ✅ SSL certificate management via Let's Encrypt (integrated)
#   ✅ JSON output support for automation
#   ✅ User-based container isolation
#   ✅ Port range management (12000-13000)
#   ✅ Log viewing and analysis
#   ✅ Nginx config regeneration
#   ✅ Security headers and optimizations
#   ✅ Container health monitoring
#   ✅ Backup and restore capabilities
#   ✅ Add/remove custom domains
#
# DEPENDENCIES: Docker, Nginx
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# =============================================================================
# UTILS (Integrated)
# =============================================================================

# Global flag for clean JSON output
JSON_OUTPUT=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { [[ $JSON_OUTPUT -eq 0 ]] && echo -e "${BLUE}[INFO]${NC} $1" >&2; }
log_success() { [[ $JSON_OUTPUT -eq 0 ]] && echo -e "${GREEN}[SUCCESS]${NC} $1" >&2; }
log_warning() { [[ $JSON_OUTPUT -eq 0 ]] && echo -e "${YELLOW}[WARNING]${NC} $1" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

validate_project_name() {
        [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]] || {
                log_error "Invalid project name"
                return 1
        }
}

validate_domain() {
        [[ -z "$1" ]] || [[ "$1" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || {
                log_error "Invalid domain"
                return 1
        }
}

check_port_available() {
        # Check if lsof is available
        if command -v lsof >/dev/null 2>&1; then
                lsof -i ":$1" >/dev/null 2>&1 && return 1 || return 0
        else
                # Fallback to ss or netstat if lsof is missing
                if command -v ss >/dev/null 2>&1; then
                        ss -lnt | grep -q ":$1 " && return 1 || return 0
                else
                        # Last resort: try to bind the port with python or nc (optional, skipping for simplicity)
                        return 0 # Assume available if we can't check
                fi
        fi
}

# =============================================================================
# GLOBAL CONFIGURATION
# =============================================================================
readonly MIN_PORT=12000
readonly MAX_PORT=13000
readonly DEFAULT_START_PORT=12000
readonly CONTAINER_NAME_PREFIX="sgtm"
readonly IMAGE_NAME="khanshifaul/gtm-unified-server:latest"
readonly CURRENT_USER_ID=$(whoami 2>/dev/null || echo "unknown")

# =============================================================================
# CORE UTILITY FUNCTIONS
# =============================================================================

build_json_object() {
        local output="{"
        local first=true
        while [[ $# -gt 0 ]]; do
                local key="$1"
                shift
                local value="$1"
                shift
                value="${value//\"/\\\"}"
                if ! $first; then output="$output,"; fi
                output="$output\"$key\":\"$value\""
                first=false
        done
        output="$output}"
        printf '%s' "$output"
}

json_write() {
        printf '%s\n' "$1"
}

validate_domain() {
        local domain="$1"
        [[ -n "$domain" ]] && [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]
}

validate_container_name() {
        local name="$1"
        [[ ! "$name" =~ ^(sgtm|container|server|tag|docker)$ ]]
}

validate_user_id() {
        local user_id="$1"
        [[ "$user_id" != "root" ]]
}

# =============================================================================
# SSL MANAGEMENT FUNCTIONS (INTEGRATED)
# =============================================================================

get_server_ip() {
        # Try multiple methods to get the server's public IP
        local ip=""

        # Method 1: Check public IP via external service
        ip=$(curl -s --connect-timeout 5 http://ifconfig.me 2>/dev/null || curl -s --connect-timeout 5 http://api.ipify.org 2>/dev/null)

        if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "$ip"
                return 0
        fi

        # Method 2: Get main interface IP
        ip=$(ip route get 1 2>/dev/null | awk '{print $7; exit}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || echo "")

        if [[ -n "$ip" ]]; then
                echo "$ip"
                return 0
        fi

        log_warning "Could not determine server IP automatically"
        return 1
}

dns_verify() {
        local DOMAIN=$1
        local EXPECTED_IP=$2

        log_info "Verifying DNS for $DOMAIN..."

        if ! command -v nslookup &>/dev/null; then
                log_warning "nslookup not available, skipping DNS verification"
                return 0
        fi

        if ! nslookup "$DOMAIN" >/dev/null 2>&1; then
                log_error "DNS lookup failed for $DOMAIN"
                return 1
        fi

        local RESOLVED_IP
        RESOLVED_IP=$(nslookup "$DOMAIN" 2>/dev/null | awk '/^Address: / { print $2 }' | tail -n1)

        if [ -z "$RESOLVED_IP" ]; then
                log_warning "Could not resolve IP for $DOMAIN"
                return 1
        fi

        if [ "$RESOLVED_IP" != "$EXPECTED_IP" ]; then
                log_warning "DNS mismatch: $DOMAIN points to $RESOLVED_IP (expected $EXPECTED_IP)"
                log_warning "SSL certificate issuance may fail if DNS is not properly configured"
                return 1
        fi

        log_success "DNS verified: $DOMAIN correctly points to $EXPECTED_IP"
        return 0
}

setup_ssl_certificates() {
        local domains="$1" custom_name="$2" port="$3"

        IFS=' ' read -ra domain_array <<<"$domains"
        local primary_domain="${domain_array[0]}"

        # Check if SSL certificate already exists and is valid
        if check_ssl_enabled "$primary_domain"; then
                log_info "SSL certificate already exists for $primary_domain"
                return 0
        fi

        local admin_email="admin@$primary_domain"
        local service_name="${custom_name}-${primary_domain}"

        log_info "Setting up SSL for $primary_domain..."

        # Get server IP for DNS verification
        local SERVER_IP
        SERVER_IP=$(get_server_ip)
        if [[ -z "$SERVER_IP" ]]; then
                log_warning "Cannot determine server IP, DNS verification skipped"
        else
                # Verify DNS before proceeding
                if ! dns_verify "$primary_domain" "$SERVER_IP"; then
                        log_warning "DNS verification failed for $primary_domain - SSL may fail"
                fi
        fi

        # Only request SSL for the primary domain
        local DOMAINS=("$primary_domain")
        local FINAL_DOMAINS="$primary_domain"

        # Temp Nginx conf for ACME challenge
        local TEMP_CONF="/etc/nginx/sites-available/${service_name}_acme"

        # Create temporary configuration for ACME challenge
        sudo tee "$TEMP_CONF" >/dev/null <<EOL
server {
    listen 80;
    server_name $primary_domain;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOL

        # Enable the temporary config
        sudo ln -sf "$TEMP_CONF" "/etc/nginx/sites-enabled/${service_name}_acme"

        # Test and reload Nginx
        if ! sudo nginx -t; then
                log_error "Nginx configuration test failed"
                sudo rm -f "/etc/nginx/sites-enabled/${service_name}_acme"
                sudo rm -f "$TEMP_CONF"
                return 1
        fi

        if ! sudo systemctl reload nginx; then
                log_error "Failed to reload Nginx"
                sudo rm -f "/etc/nginx/sites-enabled/${service_name}_acme"
                sudo rm -f "$TEMP_CONF"
                return 1
        fi

        sleep 2

        # Build certbot command
        local CERTBOT_CMD=("sudo" "certbot" "certonly" "--nginx" "--non-interactive" "--agree-tos" "--email" "$admin_email" "--no-eff-email")
        for domain in "${DOMAINS[@]}"; do
                CERTBOT_CMD+=("-d" "$domain")
        done

        log_info "Running certbot command: ${CERTBOT_CMD[*]}"

        # Try obtaining certificate
        if "${CERTBOT_CMD[@]}" 2>/dev/null; then
                log_success "SSL certificate obtained for $FINAL_DOMAINS"
        else
                log_warning "Certbot failed for $FINAL_DOMAINS - trying standalone method as fallback..."

                # Fallback to standalone method
                local STANDALONE_CMD=("sudo" "certbot" "certonly" "--standalone" "--non-interactive" "--agree-tos" "--email" "$admin_email" "--no-eff-email" "-d" "$primary_domain")

                if "${STANDALONE_CMD[@]}" 2>/dev/null; then
                        log_success "SSL certificate obtained using standalone method for $primary_domain"
                else
                        log_error "All SSL certificate issuance methods failed for $primary_domain"
                        sudo rm -f "/etc/nginx/sites-enabled/${service_name}_acme"
                        sudo rm -f "$TEMP_CONF"
                        sudo systemctl reload nginx
                        return 1
                fi
        fi

        # Cleanup temporary config
        sudo rm -f "/etc/nginx/sites-enabled/${service_name}_acme"
        sudo rm -f "$TEMP_CONF"

        if ! sudo systemctl reload nginx; then
                log_error "Failed to reload Nginx after SSL setup"
                return 1
        fi

        # Verify certificate was created
        if check_ssl_enabled "$primary_domain"; then
                log_success "✅ SSL setup completed successfully for $primary_domain"
                return 0
        else
                log_error "SSL certificate files not found after setup"
                return 1
        fi
}

check_ssl_enabled() {
        local domain="$1"
        local cert_path="/etc/letsencrypt/live/$domain"

        # Check if certificate directory exists and contains valid files
        if [[ -d "$cert_path" ]] && [[ -f "$cert_path/fullchain.pem" ]] && [[ -f "$cert_path/privkey.pem" ]]; then
                # Verify the certificates are not empty and valid
                if [[ -s "$cert_path/fullchain.pem" ]] && [[ -s "$cert_path/privkey.pem" ]]; then
                        # Basic validation - check if certificate contains expected content
                        if grep -q "BEGIN CERTIFICATE" "$cert_path/fullchain.pem" &&
                                grep -q "BEGIN PRIVATE KEY" "$cert_path/privkey.pem"; then
                                return 0
                        else
                                log_warning "SSL certificate files for $domain appear to be invalid"
                                return 1
                        fi
                else
                        log_warning "SSL certificate files for $domain are empty"
                        return 1
                fi
        fi
        return 1
}

# =============================================================================
# CONTAINER MANAGEMENT FUNCTIONS
# =============================================================================

find_containers_by_user() {
        local user_id="$1"
        docker ps -a --format '{{.Names}}' | grep -E "^${CONTAINER_NAME_PREFIX}-" | grep -- "${user_id}" | sort
}

find_container() {
        local search_term="$1" user_filter="$2"
        [[ -z "$search_term" ]] && return 1

        local candidates=()

        if [[ "$search_term" =~ ^[0-9a-f]{1,12}$ ]]; then
                mapfile -t candidates < <(docker ps -a --format '{{.ID}} {{.Names}}' | grep -i "^${search_term}" | awk '{print $2}')
        else
                mapfile -t candidates < <(docker ps -a --format '{{.Names}}' | grep -E "^${CONTAINER_NAME_PREFIX}-" | grep -F -- "$search_term")
        fi

        if [[ -n "$user_filter" ]]; then
                local filtered=()
                for container in "${candidates[@]}"; do
                        if [[ "$container" =~ ^${CONTAINER_NAME_PREFIX}-([^/-]+)- ]]; then
                                local user_id="${BASH_REMATCH[1]}"
                                [[ "$user_id" == "$user_filter" ]] && filtered+=("$container")
                        fi
                done
                candidates=("${filtered[@]}")
        fi

        [[ ${#candidates[@]} -gt 0 ]] && echo "${candidates[0]}" && return 0
        return 1
}

validate_container() {
        local container="$1"
        if [[ -z "$container" ]] || ! docker inspect "$container" &>/dev/null; then
                log_error "Container not found: $container"
                return 1
        fi
        return 0
}

extract_user_id() {
        local container_name="$1"
        if [[ "$container_name" =~ ^${CONTAINER_NAME_PREFIX}-([^-]+)- ]]; then
                echo "${BASH_REMATCH[1]}"
        else
                echo "unknown"
        fi
}

extract_container_port() {
        local container_name="$1"
        if [[ "$container_name" =~ -([0-9]+)$ ]]; then
                echo "${BASH_REMATCH[1]}"
        else
                echo ""
        fi
}

get_domains_from_nginx() {
        local container_name="$1"
        local port=$(extract_container_port "$container_name")
        if [[ -z "$port" ]]; then
                echo ""
                return
        fi

        # Find the nginx config file for this port
        local nginx_config=""
        for config_file in /etc/nginx/sites-available/*; do
                if [[ -f "$config_file" ]] && grep -q "port $port" "$config_file" 2>/dev/null; then
                        nginx_config="$config_file"
                        break
                fi
        done

        if [[ -z "$nginx_config" ]]; then
                echo ""
                return
        fi

        # Extract domains from the comment line "# Domains: ..."
        grep "^# Domains:" "$nginx_config" 2>/dev/null | sed 's/^# Domains: //' || echo ""
}

get_container_domains() {
        local container_name="$1"
        # First try to get domains from nginx config (source of truth)
        local nginx_domains=$(get_domains_from_nginx "$container_name")
        if [[ -n "$nginx_domains" ]]; then
                echo "$nginx_domains"
                return
        fi

        # Fallback to container env (for backward compatibility)
        docker inspect -f '{{.Config.Env}}' "$container_name" 2>/dev/null | grep -o 'DOMAIN=[^ ]*' | cut -d= -f2 || echo ""
}

get_container_details() {
        local container="$1"
        declare -n details_ref="$2" # nameref to associative array

        details_ref["name"]="$container"
        details_ref["full_id"]=$(docker inspect -f '{{.Id}}' "$container")
        details_ref["short_id"]="${details_ref["full_id"]:0:12}"
        details_ref["running"]=$(docker inspect -f '{{.State.Running}}' "$container")
        details_ref["status"]=$([[ "${details_ref["running"]}" == "true" ]] && echo "running" || echo "stopped")
        details_ref["started_at"]=$(docker inspect -f '{{.State.StartedAt}}' "$container")
        details_ref["image"]=$(docker inspect -f '{{.Config.Image}}' "$container")
        details_ref["domain"]=$(get_container_domains "$container" | tr ' ' ',')
        details_ref["user_id"]=$(extract_user_id "$container")
}

find_available_port() {
        local port=$DEFAULT_START_PORT
        while ((port <= MAX_PORT)); do
                if check_port_available "$port"; then
                        echo "$port"
                        return 0
                fi
                ((port++))
        done
        log_error "No available ports in range $MIN_PORT-$MAX_PORT"
        return 1
}

# =============================================================================
# NGINX MANAGEMENT FUNCTIONS
# =============================================================================

reload_nginx() {
        if nginx -t &>/dev/null; then
                systemctl reload nginx &>/dev/null
                return 0
        else
                log_error "Nginx config test failed – not reloading"
                return 1
        fi
}

generate_nginx_server_block() {
        local domain="$1" port="$2" ssl_enabled="$3"
        local cert_path="/etc/letsencrypt/live/$domain"

        # HTTP block (always present)
        cat <<EOF
server {
    listen 80;
    server_name $domain;
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF

        # HTTPS blocks if SSL enabled
        if $ssl_enabled; then
                # Standard HTTPS (443)
                cat <<EOF
server {
    listen 443 ssl http2;
    server_name $domain;

    # SSL Configuration
    ssl_certificate $cert_path/fullchain.pem;
    ssl_certificate_key $cert_path/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self' https: 'unsafe-inline' 'unsafe-eval';" always;

    # Performance
    client_max_body_size 10M;
    keepalive_timeout 30s;
    send_timeout 30s;

    # Proxy settings
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header X-Forwarded-Port \$server_port;

    # Timeouts
    proxy_connect_timeout 30s;
    proxy_send_timeout 30s;
    proxy_read_timeout 120s;
    proxy_buffer_size 16k;
    proxy_buffers 4 32k;
    proxy_busy_buffers_size 64k;
    proxy_temp_file_write_size 64k;

    # Cache control
    proxy_cache off;
    proxy_no_cache \$http_pragma \$http_authorization;
    proxy_cache_bypass \$http_pragma \$http_authorization;

    # Main routing
    location / {
        proxy_pass http://localhost:$port;

        # Service worker special handling
        location ~* ^/_/service_worker/ {
            proxy_hide_header 'Cache-Control';
            proxy_hide_header 'Pragma';
            add_header 'Cache-Control' 'no-cache, no-store, must-revalidate';
            add_header 'Service-Worker-Allowed' '/';
            proxy_pass http://localhost:$port;
        }

        # Health check
        location = /healthz {
            access_log off;
            proxy_pass http://localhost:$port/healthz;
        }

        # Metrics (local only)
        location = /metrics {
            allow 127.0.0.1;
            deny all;
            proxy_pass http://localhost:$port/metrics;
        }
    }

    # Logging
    access_log /var/log/nginx/$domain.access.log main buffer=32k flush=5m;
    error_log /var/log/nginx/$domain.error.log warn;

    # Error pages
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
        internal;
    }
}
EOF
        fi
}

regenerate_nginx_config_for_domains() {
        local domains="$1" port="$2"

        IFS=' ' read -ra domain_array <<<"$domains"
        local primary_domain="${domain_array[0]}"
        local available="/etc/nginx/sites-available/$primary_domain"
        local enabled="/etc/nginx/sites-enabled/$primary_domain"

        # Backup existing config
        local backup=""
        if [[ -f "$available" ]]; then
                backup="$available.$(date +%Y%m%d_%H%M%S).bak"
                mv "$available" "$backup" || {
                        log_error "Failed to backup config"
                        return 1
                }
        fi

        # Generate new config
        log_info "Generating nginx config for domains: $domains on port $port"
        cat >"$available" <<EOF
# Auto-generated Nginx config for GTM container on port $port
# Managed by docker-tagserver.sh
# Domains: $domains
EOF

        # Generate server blocks for each domain
        for domain in "${domain_array[@]}"; do
                local ssl_enabled=$(check_ssl_enabled "$domain" && echo true || echo false)
                generate_nginx_server_block "$domain" "$port" "$ssl_enabled"
        done >>"$available"

        # Enable site and reload
        ln -sf "$available" "$enabled"

        if reload_nginx; then
                log_success "✅ Updated Nginx config for domains: $domains"
                return 0
        else
                log_error "❌ Nginx reload failed – reverting config changes"
                # Revert changes if nginx test fails
                if [[ -n "$backup" && -f "$backup" ]]; then
                        mv "$backup" "$available"
                        ln -sf "$available" "$enabled"
                        reload_nginx
                        log_info "✅ Reverted to previous Nginx config"
                else
                        rm -f "$available" "$enabled"
                        log_warning "⚠️  Removed invalid config (no backup available)"
                fi
                return 1
        fi
}

cleanup_nginx_config() {
        local domains="$1"
        IFS=' ' read -ra domain_array <<<"$domains"

        for domain in "${domain_array[@]}"; do
                local available="/etc/nginx/sites-available/$domain"
                local enabled="/etc/nginx/sites-enabled/$domain"
                [[ -f "$available" ]] && rm -f "$available" "$enabled"
        done

        reload_nginx
}

# =============================================================================
# CONTAINER LIFECYCLE FUNCTIONS
# =============================================================================

create_container_name() {
        local user_id="$1" custom_name="$2" primary_domain="$3" port="$4"
        local sanitized_domain=$(echo "$primary_domain" | tr '.-' '__')
        echo "${CONTAINER_NAME_PREFIX}-${user_id}-${custom_name}-${sanitized_domain}-${port}"
}

run_container() {
        local container_name="$1" port="$2" domains="$3" config="$4" user_id="$5"

        log_info "Starting container: $container_name"

        docker run -d \
                --name "$container_name" \
                --restart=unless-stopped \
                -p "$port:80" \
                -e "DOMAIN=$domains" \
                -e "CONTAINER_CONFIG=$config" \
                -e "USER_ID=$user_id" \
                "$IMAGE_NAME" >/dev/null

        if [[ $? -eq 0 ]]; then
                sleep 0.5 # Wait for container to be inspectable
                return 0
        else
                return 1
        fi
}

remove_existing_container() {
        local user_id="$1" custom_name="$2" port="$3"

        local existing_container=$(docker ps -a --format 'table {{.Names}}\t{{.Ports}}' |
                grep ":$port->" | awk '{print $1}' | head -n1)

        if [[ -n "$existing_container" ]]; then
                log_info "Removing existing container: $existing_container"
                docker rm -f "$existing_container" || {
                        log_error "Failed to remove old container"
                        return 1
                }
        fi
        return 0
}

# =============================================================================
# COMMAND FUNCTIONS
# =============================================================================

run_docker_tagserver() {
        local domain="" container_config="" custom_name="" user_id="$CURRENT_USER_ID" use_json=false

        # Parse arguments
        while [[ $# -gt 0 ]]; do
                case $1 in
                -s | --subdomain)
                        IFS=',' read -ra domain_list <<<"$2"
                        for i in "${!domain_list[@]}"; do domain_list[$i]=$(echo "${domain_list[$i]}" | xargs); done
                        domain="${domain_list[*]}"
                        shift 2
                        ;;
                -c | --config)
                        container_config="$2"
                        shift 2
                        ;;
                -n | --name)
                        custom_name="$2"
                        shift 2
                        ;;
                -u | --user)
                        user_id="$2"
                        shift 2
                        ;;
                --json)
                        use_json=true
                        shift
                        ;;
                -h | --help)
                        show_docker_tagserver_help
                        return 0
                        ;;
                *)
                        log_error "Unknown option: $1"
                        return 1
                        ;;
                esac
        done

        # Validation
        [[ -z "$domain" ]] && {
                read -rp "Enter domain/subdomain(s): " domain
                [[ -z "$domain" ]] && {
                        log_error "Domain is required"
                        return 1
                }
        }
        [[ -z "$container_config" ]] && {
                read -rp "Enter container config data: " container_config
                [[ -z "$container_config" ]] && {
                        log_error "Config is required"
                        return 1
                }
        }
        [[ -z "$custom_name" ]] && {
                read -rp "Enter container name: " custom_name
                [[ -z "$custom_name" ]] && {
                        log_error "Container name is required"
                        return 1
                }
        }
        [[ -z "$user_id" ]] && {
                log_error "User ID is required"
                return 1
        }

        ! validate_container_name "$custom_name" && {
                log_error "Container name '$custom_name' is reserved"
                return 1
        }
        ! validate_user_id "$user_id" && {
                log_error "User ID cannot be 'root'"
                return 1
        }

        IFS=' ' read -ra domain_array <<<"$domain"
        for domain_item in "${domain_array[@]}"; do
                ! validate_domain "$domain_item" && {
                        log_error "Invalid domain format: '$domain_item'"
                        return 1
                }
        done

        [[ $EUID -ne 0 ]] && {
                log_error "This script must run as root to manage Nginx"
                return 1
        }

        # Find available port
        local port=$(find_available_port) || return 1
        log_info "Using port: $port"

        local primary_domain="${domain_array[0]}"
        local container_name=$(create_container_name "$user_id" "$custom_name" "$primary_domain" "$port")

        # Remove existing container if any
        remove_existing_container "$user_id" "$custom_name" "$port" || return 1

        # Setup initial Nginx config (HTTP only)
        log_info "Setting up initial Nginx configuration..."
        if ! regenerate_nginx_config_for_domains "$domain" "$port"; then
                log_error "Failed to create initial Nginx configuration"
                return 1
        fi

        # Setup SSL certificates
        log_info "Setting up SSL certificates..."
        local ssl_success=false
        if setup_ssl_certificates "$domain" "$custom_name" "$port"; then
                ssl_success=true
                log_success "✅ SSL certificates configured successfully"
        else
                log_warning "⚠️  SSL setup failed - will serve over HTTP only"
        fi

        # Regenerate Nginx config with proper SSL settings
        log_info "Updating Nginx configuration with SSL settings..."
        if ! regenerate_nginx_config_for_domains "$domain" "$port"; then
                log_error "Failed to update Nginx configuration with SSL settings"
                return 1
        fi

        # Start container
        if run_container "$container_name" "$port" "$domain" "$container_config" "$user_id"; then
                declare -A container_details
                get_container_details "$container_name" container_details

                if $use_json; then
                        json_write "$(build_json_object \
                                "name" "${container_details["name"]}" \
                                "id" "${container_details["short_id"]}" \
                                "full_id" "${container_details["full_id"]}" \
                                "status" "${container_details["status"]}" \
                                "started_at" "${container_details["started_at"]}" \
                                "image" "${container_details["image"]}" \
                                "domain" "${container_details["domain"]}" \
                                "user_id" "${container_details["user_id"]}" \
                                "ssl_enabled" "$ssl_success")"
                else
                        [[ $JSON_OUTPUT -eq 0 ]] && echo
                        log_success "✅ Container started successfully: $container_name"
                        [[ $JSON_OUTPUT -eq 0 ]] && echo
                        for domain_item in "${domain_array[@]}"; do
                                if check_ssl_enabled "$domain_item"; then
                                        log_success "🔐 Secure URL: https://$domain_item"
                                else
                                        log_warning "🌐 Insecure: http://$domain_item (SSL pending)"
                                fi
                        done
                        [[ $JSON_OUTPUT -eq 0 ]] && echo
                        log_info "📌 Showing details for the new container:"
                        get_containers -n "$container_name"
                fi
        else
                if $use_json; then
                        json_write "$(build_json_object "error" "Failed to start container" "container_name" "$container_name")"
                else
                        log_error "💥 Failed to start container"
                fi
                return 1
        fi
}

get_containers() {
        local show_all=false filter_user="" container_id="" container_name="" use_json=false

        while [[ $# -gt 0 ]]; do
                case $1 in
                -i | --id)
                        container_id="$2"
                        shift 2
                        ;;
                -n | --name)
                        container_name="$2"
                        shift 2
                        ;;
                -u | --user)
                        filter_user="$2"
                        shift 2
                        ;;
                -a | --all)
                        show_all=true
                        shift
                        ;;
                --json)
                        use_json=true
                        shift
                        ;;
                -h | --help)
                        show_docker_tagserver_help
                        return 0
                        ;;
                *)
                        log_error "Unknown option: $1"
                        return 1
                        ;;
                esac
        done

        # Single container view
        if [[ -n "$container_id" || -n "$container_name" ]]; then
                local container=""
                if [[ -n "$container_name" ]]; then
                        container="$container_name"
                else
                        container=$(find_container "$container_id")
                fi

                if ! validate_container "$container"; then
                        if $use_json; then
                                json_write "$(build_json_object "error" "Container not found" "input" "${container_id:-$container_name}")"
                        else
                                log_error "Container not found: ${container_id:-$container_name}"
                        fi
                        return 1
                fi

                declare -A container_details
                get_container_details "$container" container_details

                if $use_json; then
                        json_write "$(build_json_object \
                                "name" "${container_details["name"]}" \
                                "id" "${container_details["short_id"]}" \
                                "full_id" "${container_details["full_id"]}" \
                                "status" "${container_details["status"]}" \
                                "started_at" "${container_details["started_at"]}" \
                                "image" "${container_details["image"]}" \
                                "domain" "${container_details["domain"]}" \
                                "user_id" "${container_details["user_id"]}")"
                else
                        [[ $JSON_OUTPUT -eq 0 ]] && echo
                        log_info "📋 Details for container: $container"
                        [[ $JSON_OUTPUT -eq 0 ]] && echo -e "${GRAY}$(printf '%.0s─' {1..60})${NC}"
                        cat <<EOF
Name: ${container_details["name"]}
ID: ${container_details["short_id"]}
Full ID: ${container_details["full_id"]}
Status: ${container_details["status"]}
Started: ${container_details["started_at"]}
Image: ${container_details["image"]}
Domain: ${container_details["domain"]}
User ID: ${container_details["user_id"]}
EOF
                        [[ $JSON_OUTPUT -eq 0 ]] && echo -e "${GRAY}$(printf '%.0s─' {1..60})${NC}"
                        [[ $JSON_OUTPUT -eq 0 ]] && echo
                fi
                return 0
        fi

        # List view
        local containers=()
        if $show_all; then
                mapfile -t containers < <(docker ps -a --format '{{.Names}}' | grep -E "^${CONTAINER_NAME_PREFIX}-" | sort)
        else
                mapfile -t containers < <(find_containers_by_user "$filter_user")
        fi

        if $use_json; then
                local json_array="[" first=true
                for container in "${containers[@]}"; do
                        ! docker inspect "$container" &>/dev/null && continue

                        declare -A container_details
                        get_container_details "$container" container_details

                        local container_info=$(build_json_object \
                                "name" "${container_details["name"]}" \
                                "id" "${container_details["short_id"]}" \
                                "full_id" "${container_details["full_id"]}" \
                                "status" "${container_details["status"]}" \
                                "started_at" "${container_details["started_at"]}" \
                                "image" "${container_details["image"]}" \
                                "domain" "${container_details["domain"]}" \
                                "user_id" "${container_details["user_id"]}")

                        if $first; then
                                json_array="$json_array$container_info"
                                first=false
                        else
                                json_array="$json_array,$container_info"
                        fi
                done
                json_array="$json_array]"
                json_write "$json_array"
                return 0
        fi

        # Human-readable list
        [[ $JSON_OUTPUT -eq 0 ]] && echo
        if $show_all; then
                log_info "🔍 Listing ALL tag server containers..."
        else
                log_info "🔍 Listing containers for user: $filter_user"
        fi
        [[ $JSON_OUTPUT -eq 0 ]] && echo

        local header="NAME                  ID         STATUS     DOMAIN                              USER       STARTED"
        local line=$(printf '%.0s─' {1..140})
        [[ $JSON_OUTPUT -eq 0 ]] && echo -e "${CYAN}${header}${NC}"
        [[ $JSON_OUTPUT -eq 0 ]] && echo -e "${GRAY}${line}${NC}"

        if [[ ${#containers[@]} -eq 0 ]]; then
                [[ $JSON_OUTPUT -eq 0 ]] && echo -e "${YELLOW}📭 No containers found${NC}"
                [[ $JSON_OUTPUT -eq 0 ]] && echo
                return 0
        fi

        for container in "${containers[@]}"; do
                ! docker inspect "$container" &>/dev/null && continue

                declare -A container_details
                get_container_details "$container" container_details

                local started_ago="unknown"
                if [[ "${container_details["started_at"]}" =~ ^[0-9] ]]; then
                        local started_ts=$(date -d "${container_details["started_at"]}" +%s 2>/dev/null || echo "")
                        if [[ -n "$started_ts" && $started_ts -gt 0 ]]; then
                                local now_ts=$(date +%s)
                                local diff=$((now_ts - started_ts))
                                if ((diff < 60)); then
                                        started_ago="Just now"
                                elif ((diff < 3600)); then
                                        started_ago="$((diff / 60)) min ago"
                                elif ((diff < 86400)); then
                                        started_ago="$((diff / 3600)) hr ago"
                                else
                                        started_ago="$((diff / 86400)) day(s) ago"
                                fi
                        fi
                fi

                local display_name=$(echo "$container" | cut -c1-17)
                [[ "${#container}" -gt 17 ]] && display_name="$display_name..."

                # Truncate domain if too long for display
                local display_domain="${container_details["domain"]}"
                if [[ ${#display_domain} -gt 35 ]]; then
                        display_domain="${display_domain:0:32}..."
                fi

                [[ $JSON_OUTPUT -eq 0 ]] && printf "%-20s %-10s %-10s %-35s %-10s %s\n" \
                        "$display_name" \
                        "${container_details["short_id"]}" \
                        "${container_details["status"]}" \
                        "$display_domain" \
                        "${container_details["user_id"]}" \
                        "$started_ago"
        done
        [[ $JSON_OUTPUT -eq 0 ]] && echo
}

execute_container_operation() {
        local operation="$1" containers=() container_id="" container_name="" user_id="" use_json=false

        while [[ $# -gt 1 ]]; do
                case $2 in
                -i | --id)
                        container_id="$3"
                        shift 2
                        ;;
                -n | --name)
                        container_name="$3"
                        shift 2
                        ;;
                -u | --user)
                        user_id="$3"
                        shift 2
                        ;;
                --json)
                        use_json=true
                        shift
                        ;;
                *) shift ;;
                esac
        done

        if [[ -n "$container_id" ]]; then
                local container=$(find_container "$container_id" "$user_id")
                [[ -n "$container" ]] && containers+=("$container")
        elif [[ -n "$container_name" ]]; then
                local container=$(find_container "$container_name" "$user_id")
                [[ -n "$container" ]] && containers+=("$container")
        fi

        [[ ${#containers[@]} -eq 0 ]] && {
                log_warning "No containers specified."
                return 0
        }

        for container in "${containers[@]}"; do
                local found=$(find_container "$container" "$user_id" || echo "")
                if [[ -n "$found" ]]; then
                        if $use_json; then
                                if docker "$operation" "$found" >/dev/null; then
                                        json_write "$(build_json_object "container" "$found" "status" "$operation" "success" "true")"
                                else
                                        json_write "$(build_json_object "container" "$found" "status" "$operation" "success" "false" "error" "Failed to $operation container")"
                                fi
                        else
                                log_info "${operation^}ing container: $found"
                                if docker "$operation" "$found" >/dev/null; then
                                        log_success "✅ ${operation^}ed: $found"
                                else
                                        log_error "❌ Failed to $operation: $found"
                                fi
                        fi
                else
                        if $use_json; then
                                json_write "$(build_json_object "error" "Container not found or not owned by user" "input" "$container" "user_id" "$user_id")"
                        else
                                log_warning "⚠️  Container not found or not owned by user '$user_id': $container"
                        fi
                fi
        done
}

delete_containers() {
        local container_id="" container_name="" user_id="" use_json=false

        while [[ $# -gt 0 ]]; do
                case $1 in
                -i | --id)
                        container_id="$2"
                        shift 2
                        ;;
                -n | --name)
                        container_name="$2"
                        shift 2
                        ;;
                -u | --user)
                        user_id="$2"
                        shift 2
                        ;;
                --json)
                        use_json=true
                        shift
                        ;;
                -h | --help)
                        show_docker_tagserver_help
                        return 0
                        ;;
                *)
                        log_error "Unknown option: $1"
                        return 1
                        ;;
                esac
        done

        [[ -z "$container_id" && -z "$container_name" ]] && {
                if $use_json; then
                        json_write "$(build_json_object "error" "Container ID (-i) or name (-n) is required")"
                else
                        log_error "Container ID (-i) or name (-n) is required"
                        show_docker_tagserver_help
                fi
                return 1
        }

        local container=""
        if [[ -n "$container_name" ]]; then
                container=$(find_container "$container_name" "$user_id")
        else
                container=$(find_container "$container_id" "$user_id")
        fi

        [[ -z "$container" ]] && {
                if $use_json; then
                        json_write "$(build_json_object "error" "Container not found" "input" "${container_id:-$container_name}" "user_filter" "$user_id")"
                else
                        log_error "Container not found or not owned by user '$user_id': ${container_id:-$container_name}"
                fi
                return 1
        }

        ! validate_container "$container" && {
                if $use_json; then
                        json_write "$(build_json_object "error" "Container not found" "name" "$container")"
                else
                        log_error "Container not found: $container"
                fi
                return 1
        }

        log_info "Deleting container: $container"
        docker stop "$container" >/dev/null && docker rm "$container" >/dev/null

        if [[ $? -eq 0 ]]; then
                local domains=$(get_container_domains "$container")
                cleanup_nginx_config "$domains"

                if $use_json; then
                        json_write "$(build_json_object "container" "$container" "status" "removed" "user_id" "$user_id")"
                else
                        log_success "✅ Removed: $container"
                fi
        else
                if $use_json; then
                        json_write "$(build_json_object "container" "$container" "status" "failed")"
                else
                        log_error "❌ Failed to remove: $container"
                fi
                return 1
        fi
}

view_logs() {
        local container_id="" container_name="" user_id="" follow=false use_json=false

        while [[ $# -gt 0 ]]; do
                case $1 in
                -i | --id)
                        container_id="$2"
                        shift 2
                        ;;
                -n | --name)
                        container_name="$2"
                        shift 2
                        ;;
                -u | --user)
                        user_id="$2"
                        shift 2
                        ;;
                -f | --follow)
                        follow=true
                        shift
                        ;;
                --json)
                        use_json=true
                        shift
                        ;;
                -h | --help)
                        show_docker_tagserver_help
                        return 0
                        ;;
                *)
                        log_error "Unknown option: $1"
                        return 1
                        ;;
                esac
        done

        local container=""
        if [[ -n "$container_name" ]]; then
                container=$(find_container "$container_name" "$user_id")
        elif [[ -n "$container_id" ]]; then
                container=$(find_container "$container_id" "$user_id")
        else
                if $use_json; then
                        json_write "$(build_json_object "error" "Container ID or name required")"
                else
                        log_error "Either container ID or name must be specified"
                fi
                return 1
        fi

        [[ -z "$container" ]] && {
                if $use_json; then
                        json_write "$(build_json_object "error" "Container not found" "input" "${container_id:-$container_name}" "user_filter" "$user_id")"
                else
                        log_error "Container not found or not owned by user '$user_id': ${container_id:-$container_name}"
                fi
                return 1
        }

        ! validate_container "$container" && {
                if $use_json; then
                        json_write "$(build_json_object "error" "Container not found" "name" "$container")"
                else
                        log_error "Container not found: $container"
                fi
                return 1
        }

        if $follow; then
                if $use_json; then
                        log_error "JSON mode does not support --follow"
                        return 1
                fi
                docker logs -f "$container"
                return $?
        fi

        local logs=$(docker logs "$container" 2>&1 | tail -n 50)
        local log_lines=()
        while IFS= read -r line; do log_lines+=("$line"); done <<<"$logs"

        if $use_json; then
                local json_arr="[" first=true
                for line in "${log_lines[@]}"; do
                        line=$(printf '%s' "$line" | sed 's/"/\\"/g')
                        if ! $first; then json_arr="$json_arr,"; fi
                        json_arr="$json_arr\"$line\""
                        first=false
                done
                json_arr="$json_arr]"
                json_write "$json_arr"
                return 0
        fi

        [[ $JSON_OUTPUT -eq 0 ]] && echo
        log_info "📜 Logs for container: $container"
        [[ $JSON_OUTPUT -eq 0 ]] && echo -e "${GRAY}$(printf '%.0s─' {1..60})${NC}"
        echo "$logs"
        [[ $JSON_OUTPUT -eq 0 ]] && echo
        [[ $JSON_OUTPUT -eq 0 ]] && echo -e "${YELLOW}Showing last 50 lines. Use -f to follow logs.${NC}"
}

add_subdomain() {
        local container_id="" container_name="" user_id="" new_subdomains="" use_json=false

        while [[ $# -gt 0 ]]; do
                case $1 in
                -i | --id)
                        container_id="$2"
                        shift 2
                        ;;
                -n | --name)
                        container_name="$2"
                        shift 2
                        ;;
                -u | --user)
                        user_id="$2"
                        shift 2
                        ;;
                -s | --subdomains)
                        IFS=',' read -ra subdomain_list <<<"$2"
                        for i in "${!subdomain_list[@]}"; do subdomain_list[$i]=$(echo "${subdomain_list[$i]}" | xargs); done
                        new_subdomains="${subdomain_list[*]}"
                        shift 2
                        ;;
                --json)
                        use_json=true
                        shift
                        ;;
                -h | --help)
                        show_docker_tagserver_help
                        return 0
                        ;;
                *)
                        log_error "Unknown option: $1"
                        return 1
                        ;;
                esac
        done

        [[ -z "$new_subdomains" ]] && {
                if $use_json; then
                        json_write "$(build_json_object "error" "New subdomains (-s) are required")"
                else
                        log_error "New subdomains (-s) are required"
                fi
                return 1
        }

        [[ -z "$container_id" && -z "$container_name" ]] && {
                if $use_json; then
                        json_write "$(build_json_object "error" "Container ID (-i) or name (-n) is required")"
                else
                        log_error "Container ID (-i) or name (-n) is required"
                fi
                return 1
        }

        local container=""
        if [[ -n "$container_name" ]]; then
                container=$(find_container "$container_name" "$user_id")
        else
                container=$(find_container "$container_id" "$user_id")
        fi

        [[ -z "$container" ]] && {
                if $use_json; then
                        json_write "$(build_json_object "error" "Container not found" "input" "${container_id:-$container_name}" "user_filter" "$user_id")"
                else
                        log_error "Container not found or not owned by user '$user_id': ${container_id:-$container_name}"
                fi
                return 1
        }

        ! validate_container "$container" && {
                if $use_json; then
                        json_write "$(build_json_object "error" "Container not found" "name" "$container")"
                else
                        log_error "Container not found: $container"
                fi
                return 1
        }

        local current_domains=$(get_container_domains "$container")
        [[ -z "$current_domains" ]] && {
                if $use_json; then
                        json_write "$(build_json_object "error" "Could not extract current domains from container")"
                else
                        log_error "Could not extract current domains from container"
                fi
                return 1
        }

        local port=$(extract_container_port "$container")
        [[ -z "$port" ]] && {
                if $use_json; then
                        json_write "$(build_json_object "error" "Could not extract port from container name")"
                else
                        log_error "Could not extract port from container name"
                fi
                return 1
        }

        IFS=' ' read -ra new_domain_array <<<"$new_subdomains"
        IFS=' ' read -ra current_domain_array <<<"$current_domains"

        local all_domains=("${current_domain_array[@]}" "${new_domain_array[@]}")
        local unique_domains=() seen=()

        for domain in "${all_domains[@]}"; do
                if [[ ! " ${seen[*]} " =~ " ${domain} " ]]; then
                        seen+=("$domain")
                        unique_domains+=("$domain")
                fi
        done

        for domain in "${new_domain_array[@]}"; do
                ! validate_domain "$domain" && {
                        if $use_json; then
                                json_write "$(build_json_object "error" "Invalid domain format" "domain" "$domain")"
                        else
                                log_error "Invalid domain format: '$domain'"
                        fi
                        return 1
                }
        done

        local all_domains_str="${unique_domains[*]}"
        if ! regenerate_nginx_config_for_domains "$all_domains_str" "$port"; then
                if $use_json; then
                        json_write "$(build_json_object "error" "Failed to create Nginx configuration")"
                else
                        log_error "Failed to create Nginx configuration"
                fi
                return 1
        fi

        log_info "Added subdomains to container: $container"

        if $use_json; then
                json_write "$(build_json_object \
                        "container" "$container" \
                        "action" "subdomains_added" \
                        "new_domains" "$new_subdomains" \
                        "all_domains" "$all_domains_str")"
        else
                log_success "✅ Added subdomains to container: $container"
                log_info "All domains now configured: $all_domains_str"
        fi
}

remove_custom_domain() {
    local container_id="" container_name="" user_id="" remove_subdomains="" use_json=false

    while [[ $# -gt 0 ]]; do
        case $1 in
        -i | --id)
            container_id="$2"
            shift 2
            ;;
        -n | --name)
            container_name="$2"
            shift 2
            ;;
        -u | --user)
            user_id="$2"
            shift 2
            ;;
        -s | --subdomains)
            IFS=',' read -ra subdomain_list <<<"$2"
            for i in "${!subdomain_list[@]}"; do subdomain_list[$i]=$(echo "${subdomain_list[$i]}" | xargs); done
            remove_subdomains="${subdomain_list[*]}"
            shift 2
            ;;
        --json)
            use_json=true
            shift
            ;;
        -h | --help)
            show_docker_tagserver_help
            return 0
            ;;
        *)
            log_error "Unknown option: $1"
            return 1
            ;;
        esac
    done

    [[ -z "$remove_subdomains" ]] && {
        if $use_json; then
            json_write "$(build_json_object "error" "Subdomains to remove (-s) are required")"
        else
            log_error "Subdomains to remove (-s) are required"
        fi
        return 1
    }

    [[ -z "$container_id" && -z "$container_name" ]] && {
        if $use_json; then
            json_write "$(build_json_object "error" "Container ID (-i) or name (-n) is required")"
        else
            log_error "Container ID (-i) or name (-n) is required"
        fi
        return 1
    }

    local container=""
    if [[ -n "$container_name" ]]; then
        container=$(find_container "$container_name" "$user_id")
    else
        container=$(find_container "$container_id" "$user_id")
    fi

    [[ -z "$container" ]] && {
        if $use_json; then
            json_write "$(build_json_object "error" "Container not found" "input" "${container_id:-$container_name}" "user_filter" "$user_id")"
        else
            log_error "Container not found or not owned by user '$user_id': ${container_id:-$container_name}"
        fi
        return 1
    }

    ! validate_container "$container" && {
        if $use_json; then
            json_write "$(build_json_object "error" "Container not found" "name" "$container")"
        else
            log_error "Container not found: $container"
        fi
        return 1
    }

    local current_domains=$(get_container_domains "$container")
    [[ -z "$current_domains" ]] && {
        if $use_json; then
            json_write "$(build_json_object "error" "Could not extract current domains from container")"
        else
            log_error "Could not extract current domains from container"
        fi
        return 1
    }

    local port=$(extract_container_port "$container")
    [[ -z "$port" ]] && {
        if $use_json; then
            json_write "$(build_json_object "error" "Could not extract port from container name")"
        else
            log_error "Could not extract port from container name"
        fi
        return 1
    }

    IFS=' ' read -ra remove_domain_array <<<"$remove_subdomains"
    IFS=' ' read -ra current_domain_array <<<"$current_domains"

    # Validate that domains to remove actually exist in current configuration
    for domain_to_remove in "${remove_domain_array[@]}"; do
        if [[ ! " ${current_domain_array[*]} " =~ " ${domain_to_remove} " ]]; then
            if $use_json; then
                json_write "$(build_json_object "error" "Domain not found in container configuration" "domain" "$domain_to_remove" "current_domains" "$current_domains")"
            else
                log_error "Domain '$domain_to_remove' not found in container configuration. Current domains: $current_domains"
            fi
            return 1
        fi
    done

    # Remove the specified domains from current list
    local updated_domains=()
    for current_domain in "${current_domain_array[@]}"; do
        local should_keep=true
        for domain_to_remove in "${remove_domain_array[@]}"; do
            if [[ "$current_domain" == "$domain_to_remove" ]]; then
                should_keep=false
                break
            fi
        done
        if $should_keep; then
            updated_domains+=("$current_domain")
        fi
    done

    # Check if we have at least one domain remaining
    if [[ ${#updated_domains[@]} -eq 0 ]]; then
        if $use_json; then
            json_write "$(build_json_object "error" "Cannot remove all domains - container must have at least one domain")"
        else
            log_error "Cannot remove all domains - container must have at least one domain"
        fi
        return 1
    fi

    local updated_domains_str="${updated_domains[*]}"

    # Regenerate Nginx configuration with updated domains
    if ! regenerate_nginx_config_for_domains "$updated_domains_str" "$port"; then
        if $use_json; then
            json_write "$(build_json_object "error" "Failed to update Nginx configuration")"
        else
            log_error "Failed to update Nginx configuration"
        fi
        return 1
    fi

    # Note: We're NOT removing SSL certificates automatically because:
    # 1. The certificate might be used by other containers
    # 2. Let's Encrypt certificates are managed separately
    # 3. Manual certificate cleanup might be preferred

    if $use_json; then
        json_write "$(build_json_object \
                "container" "$container" \
                "action" "subdomains_removed" \
                "removed_domains" "$remove_subdomains" \
                "remaining_domains" "$updated_domains_str")"
    else
        log_success "✅ Removed subdomains from container: $container"
        log_info "Removed domains: $remove_subdomains"
        log_info "Remaining domains: $updated_domains_str"
        log_warning "⚠️  SSL certificates for removed domains were NOT automatically removed"
        log_info "   To cleanup SSL certificates manually, run: sudo certbot delete --cert-name $domain_to_remove"
    fi
}

count_usage() {
    local container_id="" container_name="" user_id="" use_json=false since_time="" until_time=""

    while [[ $# -gt 0 ]]; do
        case $1 in
        -i | --id)
            container_id="$2"
            shift 2
            ;;
        -n | --name)
            container_name="$2"
            shift 2
            ;;
        -u | --user)
            user_id="$2"
            shift 2
            ;;
        --since)
            since_time="$2"
            shift 2
            ;;
        --until)
            until_time="$2"
            shift 2
            ;;
        --json)
            use_json=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            return 1
            ;;
        esac
    done

    local container=""
    if [[ -n "$container_name" ]]; then
        container=$(find_container "$container_name" "$user_id")
    elif [[ -n "$container_id" ]]; then
        container=$(find_container "$container_id" "$user_id")
    else
        if $use_json; then
            json_write "$(build_json_object "error" "Container ID or name required")"
        else
            log_error "Container ID or name required"
        fi
        return 1
    fi

    [[ -z "$container" ]] || ! validate_container "$container" && {
        if $use_json; then
            json_write "$(build_json_object "error" "Container not found")"
        else
            log_error "Container not found"
        fi
        return 1
    }

    # Build docker logs command with optional time filters
    local docker_args=()
    if [[ -n "$since_time" ]]; then
        docker_args+=(--since "$since_time")
    fi
    if [[ -n "$until_time" ]]; then
        docker_args+=(--until "$until_time")
    fi

    local logs
    if [[ ${#docker_args[@]} -gt 0 ]]; then
        logs=$(docker logs "${docker_args[@]}" "$container" 2>&1)
    else
        logs=$(docker logs "$container" 2>&1)
    fi

    # Count total requests using multiple patterns to catch different log formats
    local total_requests=0

    # Pattern 1: Standard HTTP methods with paths
    total_requests=$((total_requests + $(echo "$logs" | grep -c -E "(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD) [\"']?/")))

    # Pattern 2: Common web server log formats
    total_requests=$((total_requests + $(echo "$logs" | grep -c -E "\" (GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD) ")))

    # Pattern 3: Status codes (200, 404, 500, etc.)
    if [[ $total_requests -eq 0 ]]; then
        total_requests=$((total_requests + $(echo "$logs" | grep -c -E " 200 | 404 | 500 | 302 | 301 ")))
    fi

    # Pattern 4: Common API/route indicators
    if [[ $total_requests -eq 0 ]]; then
        total_requests=$((total_requests + $(echo "$logs" | grep -c -E "(/api/|/v[0-9]/|/graphql|/rest/| endpoint| route)")))
    fi

    # Pattern 5: If still zero, count all lines as potential activity
    if [[ $total_requests -eq 0 && -n "$logs" ]]; then
        total_requests=$(echo "$logs" | wc -l)
    fi

    # Build time range info
    local time_range_info=""
    if [[ -n "$since_time" && -n "$until_time" ]]; then
        time_range_info="between $since_time and $until_time"
    elif [[ -n "$since_time" ]]; then
        time_range_info="since $since_time"
    elif [[ -n "$until_time" ]]; then
        time_range_info="until $until_time"
    fi

    if $use_json; then
        # Build JSON object with only essential fields
        local json_parts=()
        json_parts+=("\"container\":\"$container\"")
        json_parts+=("\"total_requests\":\"$total_requests\"")

        [[ -n "$time_range_info" ]] && json_parts+=("\"time_range\":\"$time_range_info\"")
        [[ -n "$since_time" ]] && json_parts+=("\"since\":\"$since_time\"")
        [[ -n "$until_time" ]] && json_parts+=("\"until\":\"$until_time\"")

        local json_output="{"
        for i in "${!json_parts[@]}"; do
            [[ $i -gt 0 ]] && json_output+=","
            json_output+="${json_parts[$i]}"
        done
        json_output+="}"

        json_write "$json_output"
    else
        [[ $JSON_OUTPUT -eq 0 ]] && echo
        log_info "📊 Usage Statistics for: $container"
        [[ $JSON_OUTPUT -eq 0 ]] && echo -e "${GRAY}$(printf '%.0s─' {1..60})${NC}"

        if [[ -n "$time_range_info" ]]; then
            log_info "Time Range: $time_range_info"
        fi

        [[ $JSON_OUTPUT -eq 0 ]] && echo
        [[ $JSON_OUTPUT -eq 0 ]] && echo -e "Total Requests: ${BOLD}$total_requests${NC}"

        [[ $JSON_OUTPUT -eq 0 ]] && echo -e "${GRAY}$(printf '%.0s─' {1..60})${NC}"
        [[ $JSON_OUTPUT -eq 0 ]] && echo
    fi
}

# =============================================================================
# HELP FUNCTION
# =============================================================================

show_docker_tagserver_help() {
    echo -e "${YELLOW}Usage:${NC}"
    echo "  docker-tagserver [command] [options]"
    echo
    echo -e "${YELLOW}Commands:${NC}"
    echo "  create / run       Start a new tag server container"
    echo "  get / list         Get or list containers"
    echo "  stop               Stop containers"
    echo "  start              Start containers"
    echo "  restart            Restart containers"
    echo "  delete             Remove containers"
    echo "  logs               View container logs"
    echo "  add-custom-domain  Add custom domains to existing container"
    echo "  remove-custom-domain Remove custom domains from existing container"
    echo "  count-usage        Count HTTP requests for container"
    echo "  help               Show this help"
    echo
    echo -e "${YELLOW}Common Options:${NC}"
    echo "  -i, --id ID            Target by container ID"
    echo "  -n, --name NAME        Target by container name"
    echo "  -u, --user USER_ID     Filter by user ID"
    echo "  -s, --subdomain(s)     Domain(s) (comma-separated for run/add)"
    echo "  -c, --config CONFIG    Container config (for run)"
    echo "  -f, --follow           Follow logs"
    echo "      --since TIME       Count requests since timestamp"
    echo "      --until TIME       Count requests until timestamp"
    echo "      --json             JSON output"
    echo "  -a, --all              Show all containers"
    echo
    echo -e "${YELLOW}Examples:${NC}"
    echo -e "${GREEN}🔹 Count usage:${NC}"
    echo "  docker-tagserver count-usage -n marketing --since 2025-10-31T18:00:00.000Z"
    echo "  docker-tagserver count-usage -n marketing --since 2025-10-31T18:00:00.000Z --until 2025-10-31T20:00:00.000Z --json"
}

# =============================================================================
# MAIN DISPATCH
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
        # Early check for --json to set global flag
        for arg in "$@"; do
                if [[ "$arg" == "--json" ]]; then
                        JSON_OUTPUT=1
                        break
                fi
        done

        CMD="${1:-help}"
        shift

        case "$CMD" in
        run | create) run_docker_tagserver "$@" ;;
        list | ls | get | info) get_containers "$@" ;;
        stop) execute_container_operation "stop" "$@" ;;
        start) execute_container_operation "start" "$@" ;;
        restart) execute_container_operation "restart" "$@" ;;
        delete | rm) delete_containers "$@" ;;
        logs) view_logs "$@" ;;
        add-custom-domain) add_subdomain "$@" ;;
        remove-custom-domain) remove_custom_domain "$@" ;;
        count-usage) count_usage "$@" ;;
        help | -h | --help) show_docker_tagserver_help ;;
        *)
                log_error "Unknown command: $CMD"
                show_docker_tagserver_help
                exit 1
                ;;
        esac
fi