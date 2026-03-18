const jwt    = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { query } = require('../config/db');

const ACCESS_SECRET  = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ACCESS_EXP     = process.env.JWT_EXPIRES_IN         || '7d';
const REFRESH_EXP    = process.env.JWT_REFRESH_EXPIRES_IN || '30d';

// ─── Sign access token (short-lived) ─────────────────────────────────────────
function signAccessToken(user) {
  return jwt.sign(
    {
      sub:  user.id,
      email: user.email,
      name:  user.display_name,
    },
    ACCESS_SECRET,
    { expiresIn: ACCESS_EXP }
  );
}

// ─── Sign + persist refresh token (long-lived) ───────────────────────────────
async function signRefreshToken(userId) {
  // Generate a cryptographically random raw token
  const rawToken = crypto.randomBytes(64).toString('hex');
  const hash     = await bcrypt.hash(rawToken, 10);

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 30);

  await query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)`,
    [userId, hash, expiresAt]
  );

  // Return a JWT that carries the raw token in its payload
  return jwt.sign({ sub: userId, raw: rawToken }, REFRESH_SECRET, { expiresIn: REFRESH_EXP });
}

// ─── Verify access token ──────────────────────────────────────────────────────
function verifyAccessToken(token) {
  return jwt.verify(token, ACCESS_SECRET);   // throws if invalid / expired
}

// ─── Rotate refresh token ─────────────────────────────────────────────────────
async function rotateRefreshToken(incomingJwt) {
  let payload;
  try {
    payload = jwt.verify(incomingJwt, REFRESH_SECRET);
  } catch {
    throw new Error('Invalid refresh token.');
  }

  // Find a valid, non-revoked token for this user
  const { rows } = await query(
    `SELECT * FROM refresh_tokens
     WHERE user_id=$1 AND revoked=FALSE AND expires_at > NOW()`,
    [payload.sub]
  );

  // Validate raw token against stored hashes
  let matchedRow = null;
  for (const row of rows) {
    const ok = await bcrypt.compare(payload.raw, row.token_hash);
    if (ok) { matchedRow = row; break; }
  }

  if (!matchedRow) throw new Error('Refresh token not found or already used.');

  // Revoke old token (rotation)
  await query('UPDATE refresh_tokens SET revoked=TRUE WHERE id=$1', [matchedRow.id]);

  // Fetch fresh user record
  const { rows: userRows } = await query('SELECT * FROM users WHERE id=$1', [payload.sub]);
  if (!userRows[0]) throw new Error('User not found.');

  const user = userRows[0];
  return {
    accessToken:  signAccessToken(user),
    refreshToken: await signRefreshToken(user.id),
    user: sanitizeUser(user),
  };
}

// ─── Revoke all tokens for a user (logout all devices) ───────────────────────
async function revokeAllTokens(userId) {
  await query('UPDATE refresh_tokens SET revoked=TRUE WHERE user_id=$1', [userId]);
}

// ─── Remove private fields before sending user to client ─────────────────────
function sanitizeUser(user) {
  const { password_hash, google_id, microsoft_id, ...safe } = user;
  return safe;
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  rotateRefreshToken,
  revokeAllTokens,
  sanitizeUser,
};
