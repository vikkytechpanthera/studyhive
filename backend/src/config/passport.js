const passport            = require('passport');
const LocalStrategy       = require('passport-local').Strategy;
const GoogleStrategy      = require('passport-google-oauth20').Strategy;
const MicrosoftStrategy   = require('passport-microsoft').Strategy;
const bcrypt              = require('bcryptjs');
const { query }           = require('./db');

// ─── SERIALIZE / DESERIALIZE (session – used only by OAuth flow) ──────────────
passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await query('SELECT * FROM users WHERE id=$1', [id]);
    done(null, rows[0] || false);
  } catch (err) {
    done(err);
  }
});

// ─── LOCAL STRATEGY (email + password) ───────────────────────────────────────
passport.use(new LocalStrategy(
  { usernameField: 'email', passwordField: 'password' },
  async (email, password, done) => {
    try {
      const { rows } = await query(
        'SELECT * FROM users WHERE email = $1 AND is_active = TRUE',
        [email.toLowerCase().trim()]
      );
      const user = rows[0];
      if (!user)               return done(null, false, { message: 'Invalid email or password.' });
      if (!user.password_hash) return done(null, false, { message: 'Please sign in with Google or Microsoft.' });

      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) return done(null, false, { message: 'Invalid email or password.' });

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

// ─── GOOGLE STRATEGY ─────────────────────────────────────────────────────────
passport.use(new GoogleStrategy(
  {
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:  process.env.GOOGLE_CALLBACK_URL,
    scope: ['profile', 'email'],
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const email       = profile.emails?.[0]?.value?.toLowerCase();
      const displayName = profile.displayName;
      const avatarUrl   = profile.photos?.[0]?.value;
      const googleId    = profile.id;

      // 1. Already linked to this Google account?
      let { rows } = await query('SELECT * FROM users WHERE google_id=$1', [googleId]);
      if (rows[0]) return done(null, rows[0]);

      // 2. Email exists – link Google to it
      ({ rows } = await query('SELECT * FROM users WHERE email=$1', [email]));
      if (rows[0]) {
        const { rows: updated } = await query(
          'UPDATE users SET google_id=$1, avatar_url=COALESCE(avatar_url,$2), is_verified=TRUE, updated_at=NOW() WHERE id=$3 RETURNING *',
          [googleId, avatarUrl, rows[0].id]
        );
        return done(null, updated[0]);
      }

      // 3. Brand-new user
      const { rows: created } = await query(
        `INSERT INTO users (email, display_name, avatar_url, google_id, is_verified)
         VALUES ($1,$2,$3,$4,TRUE) RETURNING *`,
        [email, displayName, avatarUrl, googleId]
      );
      return done(null, created[0]);
    } catch (err) {
      return done(err);
    }
  }
));

// ─── MICROSOFT STRATEGY ──────────────────────────────────────────────────────
passport.use(new MicrosoftStrategy(
  {
    clientID:     process.env.MICROSOFT_CLIENT_ID,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    callbackURL:  process.env.MICROSOFT_CALLBACK_URL,
    scope: ['user.read'],
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const email       = profile.emails?.[0]?.value?.toLowerCase();
      const displayName = profile.displayName;
      const microsoftId = profile.id;

      let { rows } = await query('SELECT * FROM users WHERE microsoft_id=$1', [microsoftId]);
      if (rows[0]) return done(null, rows[0]);

      ({ rows } = await query('SELECT * FROM users WHERE email=$1', [email]));
      if (rows[0]) {
        const { rows: updated } = await query(
          'UPDATE users SET microsoft_id=$1, is_verified=TRUE, updated_at=NOW() WHERE id=$2 RETURNING *',
          [microsoftId, rows[0].id]
        );
        return done(null, updated[0]);
      }

      const { rows: created } = await query(
        `INSERT INTO users (email, display_name, microsoft_id, is_verified)
         VALUES ($1,$2,$3,TRUE) RETURNING *`,
        [email, displayName, microsoftId]
      );
      return done(null, created[0]);
    } catch (err) {
      return done(err);
    }
  }
));

module.exports = passport;
