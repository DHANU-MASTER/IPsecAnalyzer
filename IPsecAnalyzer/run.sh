#!/bin/bash

set -e

echo "🚀 Starting IPsec VPN Analyzer..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Copying from .env.example..."
    cp .env.example .env
    echo "📝 Please update .env with your configuration"
fi

# Load environment safely: skip comments AND blank lines, handle spaces in values
set -a
while IFS='=' read -r key value; do
    key=$(echo "$key" | tr -d ' \r')
    [ -z "$key" ] && continue
    case "$key" in \#*) continue ;; esac
    [ -z "$value" ] && continue
    value=$(echo "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//')
    export "$key=$value"
done < <(grep -v '^\s*$' .env)
set +a

# Prefer docker compose v2, fall back to docker-compose
if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
else
    COMPOSE="docker-compose"
fi

echo "🐘 Starting PostgreSQL..."
$COMPOSE up -d postgres

echo "⏳ Waiting for PostgreSQL to be ready..."
sleep 10

echo "🔨 Building application..."
$COMPOSE build app

echo "🌐 Starting application..."
$COMPOSE up -d app

echo "⏳ Waiting for application to start..."
sleep 5

echo "✅ Application started!"
echo ""
echo "🎯 Dashboard: http://localhost:8080"
echo "🔐 Login: http://localhost:8080/login"
echo "📊 Health: http://localhost:8080/health"
echo ""
echo "Credentials:"
echo "  Username: admin"
echo "  Password: generated at first boot -> check .admin-credentials"
echo "  (set ADMIN_PASSWORD in .env before first boot to choose your own)"
echo ""
echo "To stop: docker compose down"
