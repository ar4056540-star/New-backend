# VYBE

VYBE uses a custom Node.js/Express backend with server-side JSON persistence and private media storage.

## Development

1. Copy `.env.example` to `.env` and set a strong `SESSION_SECRET`.
2. Run `npm install` (or `bun install`).
3. Run `npm run dev`.

The web app and API are served together on port 3000.


## Media upload limit
The custom backend controls the maximum size of profile pictures, post/story media, reels, and message attachments with `TSUKYO_MAX_UPLOAD_MB` in the server environment. The default is 512 MB when the variable is omitted or invalid. Files above the configured server-side limit receive HTTP 413.


## Deployment configuration
See [DEPLOYMENT.md](DEPLOYMENT.md) for Docker/Render deployment steps. Set `SESSION_SECRET` in production and configure `DATA_DIR` to a persistent disk mount so JSON records and uploaded media survive restarts. The included `render.yaml` uses a paid Starter service and a 1 GB persistent disk; review current host pricing before deploying.

---

## Tsukyo Android API (added)

The server now exposes the complete API used by the Tsukyo Android app: paginated feeds, stories with viewers,
Reels, comments with replies, search, follows, blocking, reporting, direct messages, group chats, unread counts,
notification preferences, account deletion and Firebase push notifications.

- Endpoint reference: `docs/API.md`
- Automated test report: `docs/TEST_REPORT.md` (`npm run test:api`)
- Data audit and cleanup: `node scripts/cleanup-data.mjs --data-dir <DATA_DIR>` (dry run by default; see the script header)
- Push notifications: set `FCM_SERVICE_ACCOUNT_JSON` (see `.env.example`)

### Behaviour changes
- New accounts are no longer marked as verified and no longer receive a default bio.
- Profile responses no longer include other users' email addresses.
- Counts (followers, following, posts, likes, comments) are calculated from the stored records on every request.
- Posts, Stories and Reels must reference media uploaded through `POST /api/media/upload` by the same user.
  Legacy base64 images from the old web client are still accepted unless `TSUKYO_ALLOW_DATA_URLS=false`.
- Server-Sent Events for conversations and notifications are delivered only to the users concerned.
