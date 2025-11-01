#!/usr/bin/env sh
set -eu

: "${MINECHARTS_API_URL:=http://localhost:30080}"
: "${SSL_CERT_PATH:=/etc/nginx/certs/tls.crt}"
: "${SSL_KEY_PATH:=/etc/nginx/certs/tls.key}"
: "${SSL_SELF_SIGNED_SUBJECT:=/CN=localhost}"
: "${ENABLE_TLS:=true}"

normalise_bool() {
    case "$(echo "$1" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on) echo "true" ;;
        *) echo "false" ;;
    esac
}

TLS_ENABLED=$(normalise_bool "${ENABLE_TLS}")

PRIMARY_LISTEN_DIRECTIVES=""
TLS_SSL_CONFIG=""
TLS_HSTS_HEADER=""
TLS_REDIRECT_SERVER=""

if [ "${TLS_ENABLED}" = "true" ]; then
    export SSL_CERT_PATH SSL_KEY_PATH
    PRIMARY_LISTEN_DIRECTIVES=$(cat <<'EOF'
        listen 443 ssl http2;
EOF
)
    TLS_SSL_CONFIG=$(cat <<EOF
        ssl_certificate     ${SSL_CERT_PATH};
        ssl_certificate_key ${SSL_KEY_PATH};
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;
EOF
)
    TLS_HSTS_HEADER='        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
    TLS_REDIRECT_SERVER=$(cat <<'EOF'
    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

EOF
)
else
    PRIMARY_LISTEN_DIRECTIVES=$(cat <<'EOF'
        listen 80;
EOF
)
    echo "INFO: TLS disabled, serving Minecharts over HTTP only."
fi

export MINECHARTS_API_URL PRIMARY_LISTEN_DIRECTIVES TLS_SSL_CONFIG TLS_HSTS_HEADER TLS_REDIRECT_SERVER

ensure_self_signed_cert() {
    cert_dir=$(dirname "${SSL_CERT_PATH}")
    key_dir=$(dirname "${SSL_KEY_PATH}")

    if [ ! -f "${SSL_CERT_PATH}" ] || [ ! -f "${SSL_KEY_PATH}" ]; then
        echo "No TLS material found, generating self-signed certificate..."
        mkdir -p "${cert_dir}" "${key_dir}"
        openssl req -x509 -nodes -days 365 \
            -newkey rsa:2048 \
            -keyout "${SSL_KEY_PATH}" \
            -out "${SSL_CERT_PATH}" \
            -subj "${SSL_SELF_SIGNED_SUBJECT}" >/dev/null 2>&1
    fi
}

render_nginx_config() {
    envsubst '${MINECHARTS_API_URL} ${SSL_CERT_PATH} ${SSL_KEY_PATH} ${PRIMARY_LISTEN_DIRECTIVES} ${TLS_SSL_CONFIG} ${TLS_HSTS_HEADER} ${TLS_REDIRECT_SERVER}' \
        < /etc/nginx/templates/nginx.conf.template \
        > /etc/nginx/nginx.conf
}

if [ "${TLS_ENABLED}" = "true" ]; then
    ensure_self_signed_cert
fi
render_nginx_config

exec "$@"
