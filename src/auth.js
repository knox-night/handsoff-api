const crypto = require('node:crypto');

const tokenSecret = process.env.HANDSOFF_TOKEN_SECRET || 'local-development-token-secret';
const tokenLifetimeSeconds = 60 * 60;

function encode(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function sign(value) {
  return crypto.createHmac('sha256', tokenSecret).update(value).digest('base64url');
}

function createToken(userId) {
  const payload = encode({
    sub: userId,
    exp: Math.floor(Date.now() / 1000) + tokenLifetimeSeconds
  });
  return `${payload}.${sign(payload)}`;
}

function verifyToken(token) {
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const expectedSignature = sign(parts[0]);
  const actualSignature = Buffer.from(parts[1]);
  const expected = Buffer.from(expectedSignature);
  if (actualSignature.length !== expected.length ||
      !crypto.timingSafeEqual(actualSignature, expected)) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    if (typeof payload.sub !== 'string' || payload.sub.length === 0 || payload.exp <= Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

module.exports = { createToken, verifyToken };
