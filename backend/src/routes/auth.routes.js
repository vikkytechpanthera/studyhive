const router  = require('express').Router();
const { body } = require('express-validator');
const passport = require('passport');
const ctrl     = require('../controllers/auth.controller');
const { requireAuth } = require('../middleware/auth');

// ── Validators ────────────────────────────────────────────────────────────────
const registerRules = [
  body('email').isEmail().normalizeEmail().withMessage('Valid email required.'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters.'),
  body('displayName').trim().notEmpty().withMessage('Display name required.'),
];

// ── Email / Password ──────────────────────────────────────────────────────────
router.post('/register', registerRules, ctrl.register);
router.post('/login',    ctrl.login);
router.post('/refresh',  ctrl.refresh);
router.post('/logout',   requireAuth, ctrl.logout);
router.get ('/me',       requireAuth, ctrl.me);

// ── Google OAuth ──────────────────────────────────────────────────────────────
router.get('/google',
  passport.authenticate('google', { scope: ['profile', 'email'], session: true })
);
router.get('/google/callback',
  passport.authenticate('google', { failureRedirect: `${process.env.FRONTEND_URL}/login?error=oauth`, session: true }),
  ctrl.oauthCallback
);

// ── Microsoft OAuth ───────────────────────────────────────────────────────────
router.get('/microsoft',
  passport.authenticate('microsoft', { session: true })
);
router.get('/microsoft/callback',
  passport.authenticate('microsoft', { failureRedirect: `${process.env.FRONTEND_URL}/login?error=oauth`, session: true }),
  ctrl.oauthCallback
);

module.exports = router;
