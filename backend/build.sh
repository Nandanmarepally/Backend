#!/usr/bin/env bash
# ── Render Build Script ───────────────────────────────────────
# This script runs automatically on every Render deploy.
# Render sets $PORT automatically; no need to set it here.
set -o errexit   # exit immediately on any error

echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

echo "🗂  Collecting static files..."
python manage.py collectstatic --no-input

echo "🛠  Running database migrations..."
python manage.py migrate

echo "✅ Build complete."
