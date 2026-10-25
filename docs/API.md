# Tsukyo API reference (used by the Android app)

All routes except `/api/health`, `/api/auth/register`, `/api/auth/login`, `/api/auth/reset-password` and `GET /api/media/:id` require `Authorization: Bearer <token>`.
Lists that support pagination accept `limit` and `before` (an ISO timestamp) and return `nextCursor`.

| Area | Routes |
|---|---|
| Auth | `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout` (body: `deviceToken`), `GET /api/auth/me`, `POST /api/auth/change-password`, `DELETE /api/users/me` (body: `password`) |
| Profile | `GET /api/users/:id`, `PATCH /api/users/:id`, `GET /api/users/search?q=`, `PATCH /api/users/me/preferences`, `GET /api/users/:id/posts`, `GET /api/users/:id/reels`, `GET /api/users/:id/followers`, `GET /api/users/:id/following` |
| Follow / block / report | `POST,DELETE /api/users/:id/follow`, `POST,DELETE /api/users/:id/block`, `GET /api/blocks`, `POST /api/reports` |
| Media | `POST /api/media/upload?folder=posts|stories|reels|avatars|messages&filename=` (raw body, `Content-Type` = file type), `GET /api/media/:id` (range requests) |
| Posts | `GET /api/feed?scope=following|all`, `GET /api/posts/:id`, `POST /api/posts`, `PATCH,DELETE /api/posts/:id`, `POST /api/posts/:id/like`, `GET /api/search?type=posts|reels&q=` |
| Stories | `GET,POST /api/stories`, `DELETE /api/stories/:id`, `POST /api/stories/:id/view`, `GET /api/stories/:id/viewers` |
| Reels | `GET,POST /api/reels`, `GET,DELETE /api/reels/:id`, `POST /api/reels/:id/like` |
| Comments | `GET,POST /api/{posts|reels}/:id/comments` (`parentId` for replies), `DELETE /api/{posts|reels}/:id/comments/:commentId` |
| Bookmarks | `GET /api/favorites`, `POST /api/favorites/:contentId` (toggle) |
| Messages | `GET,POST /api/conversations`, `GET /api/conversations/:id`, `GET,POST /api/conversations/:id/messages`, `DELETE .../messages/:messageId`, `POST .../seen`, `POST .../mute`, `GET /api/messages/unread-count` |
| Groups | `POST /api/groups`, `GET,PATCH /api/groups/:id`, `POST /api/groups/:id/members`, `DELETE /api/groups/:id/members/:userId`, `POST /api/groups/:id/leave`, `POST,DELETE /api/groups/:id/admins/:userId` |
| Notifications | `GET /api/notifications`, `GET /api/notifications/unread-count`, `POST /api/notifications/read-all`, `PATCH /api/notifications/:id` |
| Push | `POST,DELETE /api/devices` (body: `token`) |
| Realtime | `GET /api/events` (Server-Sent Events; topics `conversations:<userId>`, `messages:<conversationId>`, `notifications:<userId>`; private topics are only delivered to the intended users) |

## Push notifications
Messages and activity notifications are delivered as FCM data messages (`type`, `title`, `body`, `conversationId`, `messageId`, `unreadMessages`, ...). They are only sent when `FCM_SERVICE_ACCOUNT_JSON` (or `FCM_SERVICE_ACCOUNT_FILE`) is configured. Muted conversations, disabled notification preferences and blocked users suppress the push.

## Known limitations
- Data is stored in JSON files on the Render disk (single instance, no transactions). Move to PostgreSQL before heavy use.
- Private accounts and follow requests are not implemented.
- Password reset email is not implemented (no mail provider configured).
- Reports are stored in `reports.json` and have no admin review screen yet.
