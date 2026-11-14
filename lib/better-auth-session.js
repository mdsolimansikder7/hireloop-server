const { createHmac, timingSafeEqual } = require('node:crypto');

function getCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  const escapedName = name.replace(/([.$?*|{}()[\]\\/+^])/g, '\\$1');
  const match = cookieHeader.match(
    new RegExp('(?:^|;\\s*)' + escapedName + '=([^;]*)'),
  );
  if (!match) return null;

  try {
    return decodeURIComponent(match[1]);
  } catch {
    return null;
  }
}

function verifySignedSessionCookie(value, secret) {
  if (!value || !secret) return null;
  const signatureStart = value.lastIndexOf('.');
  if (signatureStart <= 0) return null;

  const token = value.slice(0, signatureStart);
  const signature = value.slice(signatureStart + 1);
  if (!/^[A-Za-z0-9+/]{43}=$/.test(signature)) return null;

  const expected = createHmac('sha256', secret).update(token).digest();
  const received = Buffer.from(signature, 'base64');
  if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
    return null;
  }
  return token;
}

function getBetterAuthSessionToken(cookieHeader, authorizationHeader, secret) {
  const cookie =
    getCookie(cookieHeader, '__Secure-better-auth.session_token') ??
    getCookie(cookieHeader, 'better-auth.session_token') ??
    getCookie(cookieHeader, '__Secure-better-auth-session_token') ??
    getCookie(cookieHeader, 'better-auth-session_token');
  if (cookie) return verifySignedSessionCookie(cookie, secret);

  if (typeof authorizationHeader === 'string') {
    const match = authorizationHeader.match(/^Bearer\s+(.+)$/i);
    if (match) return match[1].trim() || null;
  }
  return null;
}

module.exports = { getBetterAuthSessionToken };
