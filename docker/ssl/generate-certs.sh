#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
echo "Generating self-signed TLS certificates in $DIR..."

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$DIR/key.pem" \
  -out "$DIR/cert.pem" \
  -subj "/CN=localhost/O=NetrIQ Security"

chmod 600 "$DIR/key.pem"
chmod 644 "$DIR/cert.pem"

echo "Certificates successfully generated:"
echo "  - $DIR/cert.pem"
echo "  - $DIR/key.pem"
