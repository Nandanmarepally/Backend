#!/bin/sh
# entrypoint.sh — wait for postgres then migrate and start gunicorn

set -e

echo "Checking PostgreSQL connection..."
if [ -n "$DB_HOST" ] && [ -n "$DB_PORT" ]; then
    echo "Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT}..."
    while ! nc -z "$DB_HOST" "$DB_PORT"; do
      sleep 0.5
    done
    echo "PostgreSQL is up."
else
    echo "DB_HOST/DB_PORT not set (or using DATABASE_URL). Skipping netcat check."
fi

echo "Applying migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Starting Gunicorn..."
exec gunicorn config.wsgi:application \
  --bind 0.0.0.0:${PORT:-8000} \
  --workers 2 \
  --timeout 120
