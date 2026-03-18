-- ═══════════════════════════════════════════════
--  StudyHive Database Schema
--  Run with: psql $DATABASE_URL -f schema.sql
--  Or via: npm run db:migrate
-- ═══════════════════════════════════════════════

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── USERS ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT UNIQUE NOT NULL,
  display_name  TEXT NOT NULL,
  avatar_url    TEXT,

  -- Email/password auth
  password_hash TEXT,                        -- NULL for OAuth-only accounts

  -- OAuth providers
  google_id     TEXT UNIQUE,
  microsoft_id  TEXT UNIQUE,

  -- Profile
  institution   TEXT,
  bio           TEXT,
  is_verified   BOOLEAN NOT NULL DEFAULT FALSE,
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,

  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── REFRESH TOKENS ─────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT UNIQUE NOT NULL,          -- bcrypt hash of the raw token
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked     BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── STUDY GROUPS ───────────────────────────────────
CREATE TABLE IF NOT EXISTS groups (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  description TEXT,
  subject     TEXT,
  emoji       TEXT DEFAULT '📚',
  color       TEXT DEFAULT '#5a7ff0',
  invite_code TEXT UNIQUE DEFAULT UPPER(SUBSTRING(gen_random_uuid()::TEXT, 1, 8)),
  is_private  BOOLEAN NOT NULL DEFAULT FALSE,
  max_members INT NOT NULL DEFAULT 20,
  owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── GROUP MEMBERSHIPS ──────────────────────────────
CREATE TABLE IF NOT EXISTS group_members (
  id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id  UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role      TEXT NOT NULL DEFAULT 'member',  -- 'owner' | 'moderator' | 'member'
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(group_id, user_id)
);

-- ─── INDEXES ────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_users_email          ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_google_id      ON users(google_id);
CREATE INDEX IF NOT EXISTS idx_users_microsoft_id   ON users(microsoft_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user  ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_group_members_group  ON group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_group_members_user   ON group_members(user_id);
CREATE INDEX IF NOT EXISTS idx_groups_invite_code   ON groups(invite_code);

-- ─── AUTO-UPDATE updated_at ─────────────────────────
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'users_updated_at') THEN
    CREATE TRIGGER users_updated_at  BEFORE UPDATE ON users  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'groups_updated_at') THEN
    CREATE TRIGGER groups_updated_at BEFORE UPDATE ON groups FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
END $$;
