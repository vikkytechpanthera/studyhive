/**
 * Central error handler – must be registered last in Express.
 * Catches anything passed to next(err).
 */
function errorHandler(err, req, res, next) {
  // Log in dev, keep quiet in production
  if (process.env.NODE_ENV !== 'production') {
    console.error('💥 Error:', err.stack || err.message);
  }

  // Postgres unique-violation
  if (err.code === '23505') {
    return res.status(409).json({ error: 'A record with that value already exists.' });
  }

  // Postgres foreign-key violation
  if (err.code === '23503') {
    return res.status(400).json({ error: 'Referenced record does not exist.' });
  }

  const status = err.status || err.statusCode || 500;
  const message = status < 500
    ? err.message
    : 'Something went wrong. Please try again.';

  res.status(status).json({ error: message });
}

module.exports = errorHandler;
