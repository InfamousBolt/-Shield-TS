import jwt from 'jsonwebtoken';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

/**
 * Generate a test JWT token for testing the gateway
 */
function generateTestToken(): void {
  const privateKeyPath = join(process.cwd(), 'keys', 'private.pem');

  if (!existsSync(privateKeyPath)) {
    console.error('❌ Private key not found. Run: npm run generate-keys');
    process.exit(1);
  }

  const privateKey = readFileSync(privateKeyPath, 'utf8');

  // Token payload
  const payload = {
    sub: 'user123', // User ID
    name: 'Test User',
    email: 'test@example.com',
    iat: Math.floor(Date.now() / 1000), // Issued at
    exp: Math.floor(Date.now() / 1000) + (60 * 60), // Expires in 1 hour
  };

  // Sign token with RS256
  const signOptions: jwt.SignOptions = {
    algorithm: 'RS256',
  };

  // Only add issuer/audience if defined
  if (process.env.JWT_ISSUER) {
    signOptions.issuer = process.env.JWT_ISSUER;
  }
  if (process.env.JWT_AUDIENCE) {
    signOptions.audience = process.env.JWT_AUDIENCE;
  }

  const token = jwt.sign(payload, privateKey, signOptions);

  console.log('✅ Test JWT Token Generated:\n');
  console.log(token);
  console.log('\n📝 Token Details:');
  console.log(JSON.stringify(payload, null, 2));
  console.log('\n💡 Usage:');
  console.log('curl -H "Authorization: Bearer <token>" http://localhost:3000/api/protected');
}

// Run the script
generateTestToken();
