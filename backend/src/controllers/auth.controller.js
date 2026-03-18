const bcrypt   = require('bcryptjs');
const passport = require('passport');
const { validationResult } = require('express-validator');
const { query }            = require('../config/db');
const {
  signAccessToken,
  signRefreshToken,
  rotateRefreshToken,
  revokeAllTokens,
  sanitizeUser,
} = require('../utils/jwt');

// ─── Helpers ──────────────────────────────────────────────────────────────────
function setRefreshCookie(res, token) {
  res.cookie('refreshToken', token, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge:   30 * 24 * 60 * 60 * 1000,   // 30 days
    path:     '/api/auth',
  });
}

function tokenResponse(res, user, refreshToken) {
  setRefreshCookie(res, refreshToken);
  return res.json({
    accessToken: signAccessToken(user),
    user:        sanitizeUser(user),
  });
}

// ─── POST /api/auth/register ──────────────────────────────────────────────────
async function register(req, res, next) {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const { email, password, displayName } = req.body;
    const normalEmail = email.toLowerCase().trim();

    const { rows: existing } = await query(
      'SELECT id FROM users WHERE email=$1', [normalEmail]
    );
    if (existing[0]) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }

    const hash = await bcrypt.hash(password, 12);
    const { rows } = await query(
      `INSERT INTO users (email, display_name, password_hash)
       VALUES ($1,$2,$3) RETURNING *`,
      [normalEmail, displayName.trim(), hash]
    );
    const user = rows[0];
    const refreshToken = await signRefreshToken(user.id);
    return tokenResponse(res.status(201), user, refreshToken);
  } catch (err) {
    next(err);
  }
}

// ─── POST /api/auth/login ─────────────────────────────────────────────────────
function login(req, res, next) {
  passport.authenticate('local', { session: false }, async (err, user, info) => {
    if (err)    return next(err);
    if (!user)  return res.status(401).json({ error: info?.message || 'Login failed.' });

    try {
      const refreshToken = await signRefreshToken(user.id);
      return tokenResponse(res, user, refreshToken);
    } catch (err) {
      next(err);
    }
  })(req, res, next);
}

// ─── POST /api/auth/refresh ───────────────────────────────────────────────────
async function refresh(req, res, next) {
  try {
    const token = req.cookies?.refreshToken || req.body?.refreshToken;
    if (!token) return res.status(401).json({ error: 'No refresh token.' });

    const result = await rotateRefreshToken(token);
    setRefreshCookie(res, result.refreshToken);
    return res.json({ accessToken: result.accessToken, user: result.user });
  } catch (err) {
    return res.status(401).json({ error: err.message });
  }
}

// ─── POST /api/auth/logout ────────────────────────────────────────────────────
async function logout(req, res, next) {
  try {
    if (req.user) await revokeAllTokens(req.user.id);
    res.clearCookie('refreshToken', { path: '/api/auth' });
    return res.json({ message: 'Logged out successfully.' });
  } catch (err) {
    next(err);
  }
}

// ─── GET /api/auth/me ─────────────────────────────────────────────────────────
function me(req, res) {
  return res.json({ user: sanitizeUser(req.user) });
}

// ─── OAuth callbacks (Google + Microsoft) ────────────────────────────────────
async function oauthCallback(req, res, next) {
  try {
    const user = req.user;   // set by Passport after successful OAuth
    const refreshToken = await signRefreshToken(user.id);
    setRefreshCookie(res, refreshToken);

    const accessToken = signAccessToken(user);
    // Redirect to frontend with token in query string (frontend stores in memory)
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    return res.redirect(`${frontendUrl}/auth/callback?token=${accessToken}`);
  } catch (err) {
    next(err);
  }
}

module.exports = { register, login, refresh, logout, me, oauthCallback };
