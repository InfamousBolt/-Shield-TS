import { generateKeyPairSync } from 'crypto';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

/**
 * Generate RS256 key pair for JWT signing
 */
function generateKeys(): void {
  console.log('Generating RS256 key pair for JWT...');

  // Ensure keys directory exists
  const keysDir = join(process.cwd(), 'keys');
  if (!existsSync(keysDir)) {
    mkdirSync(keysDir, { recursive: true });
    console.log(`Created directory: ${keysDir}`);
  }

  // Generate RS256 key pair
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  // Write keys to files
  const publicKeyPath = join(keysDir, 'public.pem');
  const privateKeyPath = join(keysDir, 'private.pem');

  writeFileSync(publicKeyPath, publicKey);
  writeFileSync(privateKeyPath, privateKey);

  console.log(`Public key written to: ${publicKeyPath}`);
  console.log(`Private key written to: ${privateKeyPath}`);
  console.log('\n⚠️  IMPORTANT: Keep the private key secure and never commit it to version control!');
  console.log('✅ Key generation complete!');
}

// Run the script
generateKeys();
