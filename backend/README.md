# 🐝 StudyHive – Backend API

Node.js + Express + PostgreSQL backend with Email/Password, Google OAuth, and Microsoft OAuth.

---

## Tech Stack

| Layer | Choice |
|-------|--------|
| Runtime | Node.js 18+ |
| Framework | Express 4 |
| Database | PostgreSQL 15 |
| Auth | JWT (access + refresh) + Passport.js |
| OAuth | Google, Microsoft |
| Deploy | Render / Railway |

---

## Project Structure

```
src/
  config/
    db.js           # pg Pool + query helper + transaction helper
    migrate.js      # runs sql/schema.sql against the DB
    passport.js     # Local, Google, Microsoft strategies
  controllers/
    auth.controller.js    # register, login, refresh, logout, OAuth callback
    groups.controller.js  # CRUD + join/leave/roles
  middleware/
    auth.js         # requireAuth (JWT) + requireGroupRole
    errorHandler.js # central error handler
  routes/
    auth.routes.js
    groups.routes.js
  utils/
    jwt.js          # sign / verify / rotate tokens
  index.js          # Express app entry point
sql/
  schema.sql        # full DB schema (idempotent – safe to re-run)
```

---

## Local Development

### 1. Clone & install
```bash
git clone <your-repo>
cd studyhive-backend
npm install
```

### 2. Environment
```bash
cp .env.example .env
# Fill in DATABASE_URL, JWT_SECRET, etc.
```

### 3. Create local Postgres database
```bash
createdb studyhive
```

### 4. Run migrations
```bash
npm run db:migrate
```

### 5. Start dev server
```bash
npm run dev   # uses nodemon for auto-reload
```

The API will be live at `http://localhost:3000`.

---

## API Endpoints

### Auth
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/register` | – | Create account (email+password) |
| POST | `/api/auth/login` | – | Login → access + refresh tokens |
| POST | `/api/auth/refresh` | cookie | Rotate refresh token |
| POST | `/api/auth/logout` | ✅ | Revoke all tokens |
| GET  | `/api/auth/me` | ✅ | Get current user |
| GET  | `/api/auth/google` | – | Start Google OAuth |
| GET  | `/api/auth/microsoft` | – | Start Microsoft OAuth |

### Groups
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET    | `/api/groups` | member | My groups |
| POST   | `/api/groups` | member | Create group |
| POST   | `/api/groups/join` | member | Join via invite code |
| GET    | `/api/groups/:id` | member | Get group details |
| PATCH  | `/api/groups/:id` | owner | Update group |
| DELETE | `/api/groups/:id` | owner | Delete group |
| GET    | `/api/groups/:id/members` | member | List members |
| DELETE | `/api/groups/:id/leave` | member | Leave group |
| PATCH  | `/api/groups/:id/members/:userId/role` | moderator | Change role |

---

## Token Flow

```
Register/Login → { accessToken } + refreshToken cookie
                         │
              Send in every request:
              Authorization: Bearer <accessToken>
                         │
              Access token expires (7d) →
              POST /api/auth/refresh  (cookie sent automatically)
              ← new accessToken + rotated cookie
```

---

## Deploy to Render

1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → New → Blueprint
3. Connect your repo — Render detects `render.yaml` automatically
4. It creates: **Web Service** + **PostgreSQL** database
5. In the web service → Environment, fill in all `sync: false` secrets
6. Click **Deploy** — Render runs `npm install` then `npm start`
7. After first deploy, run migrations:
   ```bash
   # In Render dashboard → Shell
   npm run db:migrate
   ```

### OAuth Callback URLs to register
After deploy your service URL will be something like `https://studyhive-api.onrender.com`.

**Google** (console.cloud.google.com):
- Authorised redirect URI: `https://studyhive-api.onrender.com/api/auth/google/callback`

**Microsoft** (portal.azure.com → App registrations):
- Redirect URI: `https://studyhive-api.onrender.com/api/auth/microsoft/callback`

---

## Deploy to Railway

```bash
npm install -g @railway/cli
railway login
railway init
railway add postgresql
railway up
```
Then set all env vars in the Railway dashboard.

---

## Security Notes

- Passwords hashed with **bcrypt** (cost factor 12)
- Refresh tokens stored as **bcrypt hashes** — raw token never hits the DB
- Refresh tokens are **rotated** on every use (reuse = revoked)
- Rate limiting on `/login` and `/register` (20 req / 15 min)
- `helmet` sets secure HTTP headers
- CORS locked to `FRONTEND_URL`

---

## Next Steps (coming up in build series)

- [ ] Real-time chat with Socket.io
- [ ] Live whiteboard sync (multi-user canvas)
- [ ] Video/voice calls with WebRTC + mediasoup
