const { validationResult } = require('express-validator');
const { query, withTransaction } = require('../config/db');
const { sanitizeUser }           = require('../utils/jwt');

// ─── GET /api/groups  (groups the auth user belongs to) ──────────────────────
async function listMyGroups(req, res, next) {
  try {
    const { rows } = await query(
      `SELECT g.*, gm.role, gm.joined_at,
              COUNT(DISTINCT gm2.user_id)::INT AS member_count
       FROM groups g
       JOIN group_members gm  ON gm.group_id = g.id AND gm.user_id = $1
       JOIN group_members gm2 ON gm2.group_id = g.id
       GROUP BY g.id, gm.role, gm.joined_at
       ORDER BY gm.joined_at DESC`,
      [req.user.id]
    );
    res.json({ groups: rows });
  } catch (err) {
    next(err);
  }
}

// ─── POST /api/groups ─────────────────────────────────────────────────────────
async function createGroup(req, res, next) {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const { name, description, subject, emoji, color, isPrivate, maxMembers } = req.body;

    const group = await withTransaction(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO groups (name, description, subject, emoji, color, is_private, max_members, owner_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
        [name, description, subject, emoji || '📚', color || '#5a7ff0', isPrivate || false, maxMembers || 20, req.user.id]
      );
      const g = rows[0];
      // Creator auto-joins as owner
      await client.query(
        `INSERT INTO group_members (group_id, user_id, role) VALUES ($1,$2,'owner')`,
        [g.id, req.user.id]
      );
      return g;
    });

    res.status(201).json({ group });
  } catch (err) {
    next(err);
  }
}

// ─── GET /api/groups/:groupId ─────────────────────────────────────────────────
async function getGroup(req, res, next) {
  try {
    const { rows } = await query(
      `SELECT g.*,
              COUNT(DISTINCT gm.user_id)::INT AS member_count
       FROM groups g
       LEFT JOIN group_members gm ON gm.group_id = g.id
       WHERE g.id = $1
       GROUP BY g.id`,
      [req.params.groupId]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Group not found.' });
    res.json({ group: rows[0] });
  } catch (err) {
    next(err);
  }
}

// ─── PATCH /api/groups/:groupId ───────────────────────────────────────────────
async function updateGroup(req, res, next) {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const allowed = ['name','description','subject','emoji','color','is_private','max_members'];
    const sets = [], values = [];
    allowed.forEach((col) => {
      const key = col.replace(/_([a-z])/g, (_,c) => c.toUpperCase()); // camelCase
      if (req.body[key] !== undefined) {
        sets.push(`${col}=$${values.length + 1}`);
        values.push(req.body[key]);
      }
    });
    if (!sets.length) return res.status(400).json({ error: 'Nothing to update.' });

    values.push(req.params.groupId);
    const { rows } = await query(
      `UPDATE groups SET ${sets.join(',')} WHERE id=$${values.length} RETURNING *`,
      values
    );
    res.json({ group: rows[0] });
  } catch (err) {
    next(err);
  }
}

// ─── DELETE /api/groups/:groupId ──────────────────────────────────────────────
async function deleteGroup(req, res, next) {
  try {
    await query('DELETE FROM groups WHERE id=$1', [req.params.groupId]);
    res.json({ message: 'Group deleted.' });
  } catch (err) {
    next(err);
  }
}

// ─── GET /api/groups/:groupId/members ────────────────────────────────────────
async function listMembers(req, res, next) {
  try {
    const { rows } = await query(
      `SELECT u.id, u.email, u.display_name, u.avatar_url, u.institution,
              gm.role, gm.joined_at
       FROM group_members gm
       JOIN users u ON u.id = gm.user_id
       WHERE gm.group_id = $1
       ORDER BY gm.joined_at ASC`,
      [req.params.groupId]
    );
    res.json({ members: rows });
  } catch (err) {
    next(err);
  }
}

// ─── POST /api/groups/join  (by invite code) ─────────────────────────────────
async function joinByInvite(req, res, next) {
  try {
    const { inviteCode } = req.body;
    if (!inviteCode) return res.status(400).json({ error: 'Invite code required.' });

    const { rows: gRows } = await query(
      `SELECT g.*, COUNT(gm.user_id)::INT AS member_count
       FROM groups g
       LEFT JOIN group_members gm ON gm.group_id = g.id
       WHERE g.invite_code = $1
       GROUP BY g.id`,
      [inviteCode.toUpperCase()]
    );
    const group = gRows[0];
    if (!group) return res.status(404).json({ error: 'Invalid invite code.' });
    if (group.member_count >= group.max_members) {
      return res.status(409).json({ error: 'Group is full.' });
    }

    await query(
      `INSERT INTO group_members (group_id, user_id) VALUES ($1,$2)
       ON CONFLICT DO NOTHING`,
      [group.id, req.user.id]
    );
    res.json({ group });
  } catch (err) {
    next(err);
  }
}

// ─── DELETE /api/groups/:groupId/leave ───────────────────────────────────────
async function leaveGroup(req, res, next) {
  try {
    const { rows } = await query(
      'SELECT role FROM group_members WHERE group_id=$1 AND user_id=$2',
      [req.params.groupId, req.user.id]
    );
    if (rows[0]?.role === 'owner') {
      return res.status(400).json({ error: 'Transfer ownership before leaving.' });
    }
    await query(
      'DELETE FROM group_members WHERE group_id=$1 AND user_id=$2',
      [req.params.groupId, req.user.id]
    );
    res.json({ message: 'Left the group.' });
  } catch (err) {
    next(err);
  }
}

// ─── PATCH /api/groups/:groupId/members/:userId/role ─────────────────────────
async function updateMemberRole(req, res, next) {
  try {
    const { role } = req.body;
    const valid = ['member', 'moderator', 'owner'];
    if (!valid.includes(role)) return res.status(400).json({ error: 'Invalid role.' });

    await query(
      'UPDATE group_members SET role=$1 WHERE group_id=$2 AND user_id=$3',
      [role, req.params.groupId, req.params.userId]
    );
    res.json({ message: 'Role updated.' });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  listMyGroups, createGroup, getGroup, updateGroup, deleteGroup,
  listMembers, joinByInvite, leaveGroup, updateMemberRole,
};
