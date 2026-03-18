require('dotenv').config();

const express      = require('express');
const helmet       = require('helmet');
const cors         = require('cors');
const morgan       = require('morgan');
const cookieParser = require('cookie-parser');
const session      = require('express-session');
const rateLimit    = require('express-rate-limit');

const passport     = require('./config/passport');
const authRoutes   = require('./routes/auth.routes');
const groupRoutes  = require('./routes/groups.routes');
const errorHandler = require('./middleware/errorHandler');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Trust proxy (required for Railway / Render) ─────────────────────────────
app.set('trust proxy', 1);

// ─── Security headers ────────────────────────────────────────────────────────
app.use(helmet());

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (file://, Postman, mobile apps)
    if (!origin) return callback(null, true);
    const allowed = [
      'http://localhost:5173',
      'http://localhost:3000',
      'http://127.0.0.1:5173',
      process.env.FRONTEND_URL,
    ].filter(Boolean);
    if (allowed.includes(origin)) return callback(null, true);
    return callback(null, true); // allow all origins in dev
  },
  credentials: true,
}));


// ─── Request parsing ──────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ─── Logging ─────────────────────────────────────────────────────────────────
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// ─── Session (Passport OAuth needs sessions briefly during redirect) ──────────
app.use(session({
  secret:            process.env.SESSION_SECRET || 'fallback-secret',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    maxAge:   5 * 60 * 1000,   // 5 minutes – just long enough for OAuth handshake
  },
}));

// ─── Passport ────────────────────────────────────────────────────────────────
app.use(passport.initialize());
app.use(passport.session());

// ─── Rate limiting ────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  max: 20,
  message: { error: 'Too many requests, please try again later.' },
});
app.use('/api/auth/login',    authLimiter);
app.use('/api/auth/register', authLimiter);

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/auth',   authRoutes);
app.use('/api/groups', groupRoutes);

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: `Route ${req.method} ${req.path} not found.` }));

// ─── Error handler ────────────────────────────────────────────────────────────
app.use(errorHandler);

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🐝 StudyHive API running on port ${PORT} [${process.env.NODE_ENV || 'development'}]`);
});

module.exports = app;
