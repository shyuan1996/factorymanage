import crypto from 'node:crypto';

const [password, secret] = process.argv.slice(2);
if (!password || !secret) {
  console.error('Usage: node scripts/hash-password.mjs <password> <session-secret>');
  process.exit(1);
}
console.log(crypto.createHash('sha256').update(`${secret}:${password}`, 'utf8').digest('base64url'));
