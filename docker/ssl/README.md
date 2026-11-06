# NetrIQ Reverse Proxy TLS Certificates

This directory holds the SSL/TLS certificates used by the Nginx reverse proxy.

## File Requirements
- `cert.pem`: Public X.509 certificate (or full certificate chain).
- `key.pem`: Private key (RSA 2048+ or ECDSA P-256).

## Generating Development Certificates
To generate a new self-signed certificate for local testing, run:
```bash
bash generate-certs.sh
```
or via OpenSSL:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem \
  -subj "/CN=localhost/O=NetrIQ Security"
```

## Production Deployment
In production:
1. Replace `cert.pem` and `key.pem` with certificates issued by a trusted Certificate Authority (e.g., Let's Encrypt, Cloudflare, DigiCert).
2. Set permissions to `chmod 600 key.pem` and `chmod 644 cert.pem`.
3. Mount the certificates read-only in `docker-compose.yml`:
   ```yaml
   volumes:
     - ./docker/ssl:/etc/nginx/ssl:ro
   ```
