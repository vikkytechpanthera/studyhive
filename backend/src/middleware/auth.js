const { verifyAccessToken } = require('../utils/jwt');
const { query }             = require('../config/db');

/**
 * requireAuth – attaches req.user from JWT.
 * Expects: Authorization: Bearer <token>
 */
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided.' });
    }

    const token   = header.slice(7);
    const payload = verifyAccessToken(token);

    // Fetch fresh user to catch deactivated accounts
    const { rows } = await query(
      'SELECT * FROM users WHERE id=$1 AND is_active=TRUE',
      [payload.sub]
    );
    if (!rows[0]) return res.status(401).json({ error: 'Account not found or deactivated.' });

    req.user = rows[0];
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired.', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Invalid token.' });
  }
}

/**
 * requireGroupRole – use after requireAuth.
 * Checks the caller has the required role in the group (from req.params.groupId).
 * roles: ['member','moderator','owner']  — each includes all lower roles.
 */
function requireGroupRole(...allowedRoles) {
  return async (req, res, next) => {
    try {
      const groupId = req.params.groupId;
      const { rows } = await query(
        'SELECT role FROM group_members WHERE group_id=$1 AND user_id=$2',
        [groupId, req.user.id]
      );
      const membership = rows[0];
      if (!membership) {
        return res.status(403).json({ error: 'You are not a member of this group.' });
      }

      const hierarchy = ['member', 'moderator', 'owner'];
      const userLevel = hierarchy.indexOf(membership.role);
      const minLevel  = Math.min(...allowedRoles.map(r => hierarchy.indexOf(r)));

      if (userLevel < minLevel) {
        return res.status(403).json({ error: 'Insufficient permissions.' });
      }

      req.membership = membership;
      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = { requireAuth, requireGroupRole };
