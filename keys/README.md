# JWT Keys Directory

This directory contains RSA key pairs for JWT signing and verification.

## ⚠️ Security Notice

The actual key files (`.pem`, `.key`) are **git-ignored** and should never be committed to version control.

## Generating Keys

Run the following command to generate a new RSA key pair:

```bash
npm run generate-keys
```

This will create:
- `private.pem` - Private key for signing JWTs (2048-bit RSA)
- `public.pem` - Public key for verifying JWTs

## Production Deployment

For production:
1. Generate keys on the production server (never copy keys from development)
2. Store the private key securely (e.g., in a secrets manager like AWS Secrets Manager, HashiCorp Vault)
3. Ensure proper file permissions (`chmod 600` for private key)
4. Rotate keys regularly according to your security policy

## Key Format

The keys use RSA 2048-bit encryption with PKCS#8 format for maximum compatibility with JWT libraries.
