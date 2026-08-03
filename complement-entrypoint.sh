#!/bin/bash
set -e

# Complement sets SERVER_NAME (e.g. "hs1") and mounts its CA at
# /complement/ca/ca.crt + ca.key. We serve the client API on 8008 (HTTP) and
# federation on 8448 (HTTPS) with a cert signed by that CA.

SERVER_NAME="${SERVER_NAME:-localhost}"
PORT="${PORT:-8008}"
FED_PORT="${FED_PORT:-8448}"

echo "Starting scandiaca for Complement (SERVER_NAME=$SERVER_NAME)"

CA_CERT="/complement/ca/ca.crt"
CA_KEY="/complement/ca/ca.key"
SERVER_CERT="/tmp/server.crt"
SERVER_KEY="/tmp/server.key"

if [ -f "$CA_CERT" ] && [ -f "$CA_KEY" ]; then
    echo "Generating server TLS cert from Complement CA..."
    openssl genrsa -out "$SERVER_KEY" 2048 2>/dev/null
    openssl req -new -key "$SERVER_KEY" -out /tmp/server.csr -subj "/CN=$SERVER_NAME" 2>/dev/null
    cat > /tmp/server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,nonRepudiation,keyEncipherment
subjectAltName=DNS:$SERVER_NAME,IP:127.0.0.1
EOF
    openssl x509 -req -in /tmp/server.csr \
        -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
        -out "$SERVER_CERT" -days 1 -extfile /tmp/server.ext 2>/dev/null
    export TLS_CERT="$SERVER_CERT"
    export TLS_KEY="$SERVER_KEY"
    export FED_PORT="$FED_PORT"
    echo "TLS cert generated for $SERVER_NAME (federation on :$FED_PORT)"
else
    echo "No Complement CA found; running without federation TLS"
fi

export SERVER_NAME
export PORT
# SQLite backend (incremental per-row event persistence + coalescing writer), now
# fast enough for Complement's parallel load. Cap tokio worker threads: Complement
# runs many test containers concurrently and doesn't CPU-limit them, so without a
# cap each container would spawn one worker per host core and oversubscribe.
export STORAGE=sqlite
export DATABASE_PATH=/tmp/matrix.db
export TOKIO_WORKER_THREADS=2
export DISABLE_RATE_LIMIT=1
export SCRYPT_COST=2

# Complement copies appservice registration YAML files to /complement/appservice/.
# scandiaca parses that directory directly at startup (no Node needed).
if [ -d /complement/appservice ]; then
    export APPSERVICE_REGISTRATION_DIR=/complement/appservice
    echo "Appservice registration dir: $APPSERVICE_REGISTRATION_DIR"
fi

exec scandiaca
