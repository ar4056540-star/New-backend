import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';

dotenv.config();

const ROOT = process.cwd();
// Set DATA_DIR to a persistent mounted directory in production hosting.
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'backend', 'data'));
const MEDIA_DIR = path.join(DATA_DIR, 'media');
const PORT = Number(process.env.PORT || 3000);
const DEFAULT_MAX_UPLOAD_MB = 512;
const configuredMaxUploadMb = Number.parseFloat(process.env.TSUKYO_MAX_UPLOAD_MB || '');
const MAX_UPLOAD_MB = Number.isFinite(configuredMaxUploadMb) && configuredMaxUploadMb > 0 ? configuredMaxUploadMb : DEFAULT_MAX_UPLOAD_MB;
const MAX_UPLOAD_BYTES = Math.floor(MAX_UPLOAD_MB * 1024 * 1024);
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-in-production';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

if (IS_PRODUCTION && SESSION_SECRET === 'change-me-in-production') {
  throw new Error('SESSION_SECRET must be set in production.');
}

for (const dir of [DATA_DIR, MEDIA_DIR]) fs.mkdirSync(dir, { recursive: true });

const files = {
  users: path.join(DATA_DIR, 'users.json'),
  posts: path.join(DATA_DIR, 'posts.json'),
  reels: path.join(DATA_DIR, 'reels.json'),
  stories: path.join(DATA_DIR, 'stories.json'),
  comments: path.join(DATA_DIR, 'comments.json'),
  conversations: path.join(DATA_DIR, 'conversations.json'),
  messages: path.join(DATA_DIR, 'messages.json'),
  notifications: path.join(DATA_DIR, 'notifications.json'),
  follows: path.join(DATA_DIR, 'follows.json'),
  favorites: path.join(DATA_DIR, 'favorites.json'),
  appLocks: path.join(DATA_DIR, 'app-locks.json'),
  sessions: path.join(DATA_DIR, 'sessions.json'),
  media: path.join(DATA_DIR, 'media.json'),
  reactions: path.join(DATA_DIR, 'reactions.json'),
  blocks: path.join(DATA_DIR, 'blocks.json'),
  reports: path.join(DATA_DIR, 'reports.json'),
  devices: path.join(DATA_DIR, 'devices.json'),
} as const;

type Store = Record<string, any[]>;
const stores: Store = {};
for (const [key, file] of Object.entries(files)) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    stores[key] = Array.isArray(parsed) ? parsed : [];
  } catch {
    stores[key] = [];
    fs.writeFileSync(file, '[]');
  }
}

const writeQueue = new Map<string, Promise<void>>();
async function persist(key: keyof typeof files) {
  const previous = writeQueue.get(key) || Promise.resolve();
  const next = previous.then(async () => {
    const file = files[key];
    const temp = `${file}.tmp`;
    await fs.promises.writeFile(temp, JSON.stringify(stores[key], null, 2), 'utf8');
    await fs.promises.rename(temp, file);
  });
  writeQueue.set(key, next.catch(() => {}));
  return next;
}

function id(prefix: string) {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
}
function now() { return new Date().toISOString(); }
function normalizeEmail(email: string) { return String(email || '').trim().toLowerCase(); }
function sanitizeUsername(value: string) { return String(value || '').trim().toLowerCase().replace(/[^a-z0-9_.]/g, '').slice(0, 30); }
function publicUser(user: any, includePrivate = false) {
  if (!user) return null;
  const { passwordHash, passwordSalt, appLockHash, email, notificationPrefs, ...safe } = user;
  const out: any = {
    ...safe,
    followerCount: stores.follows.filter(f => f.targetUserId === user.userId).length,
    followingCount: stores.follows.filter(f => f.userId === user.userId).length,
    postCount: stores.posts.filter(p => p.ownerId === user.userId).length,
    reelCount: stores.reels.filter(r => r.ownerId === user.userId).length,
  };
  if (includePrivate) { out.email = email; out.notificationPrefs = prefsOf(user); }
  return out;
}
function passwordHash(password: string, salt?: string) {
  const usedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, usedSalt, 64).toString('hex');
  return { hash, salt: usedSalt };
}
function safeEqualHex(a: string, b: string) {
  const aa = Buffer.from(a, 'hex'); const bb = Buffer.from(b, 'hex');
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function sessionDigest(token: string) { return crypto.createHmac('sha256', SESSION_SECRET).update(token).digest('hex'); }
function createSession(userId: string) {
  const token = crypto.randomBytes(48).toString('base64url');
  stores.sessions = stores.sessions.filter(s => new Date(s.expiresAt).getTime() > Date.now());
  stores.sessions.push({ tokenHash: sessionDigest(token), userId, createdAt: now(), expiresAt: new Date(Date.now() + SESSION_TTL_MS).toISOString() });
  void persist('sessions');
  return token;
}
function getToken(req: Request) {
  const header = req.header('authorization');
  return header?.startsWith('Bearer ') ? header.slice(7) : '';
}
function userFromRequest(req: Request) {
  const token = getToken(req);
  if (!token) return null;
  const session = stores.sessions.find(s => s.tokenHash === sessionDigest(token) && new Date(s.expiresAt).getTime() > Date.now());
  return session ? stores.users.find(u => u.userId === session.userId) || null : null;
}
function requireAuth(req: Request, res: Response, next: NextFunction) {
  const user = userFromRequest(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  (req as any).user = user;
  next();
}
function validateString(value: any, max: number) { return typeof value === 'string' && value.trim().length <= max; }
function clampCount(n: any) { return Math.max(0, Number(n) || 0); }

/* ---- helpers ---- */
function me(req: Request) { return (req as any).user; }
function pageParams(req: Request, fallback = 50) {
  const limit = Math.min(100, Math.max(1, Number(req.query.limit) || fallback));
  const before = typeof req.query.before === 'string' ? req.query.before : '';
  return { limit, before };
}
function paginate<T extends { createdAt: string }>(items: T[], limit: number, before: string) {
  const sorted = [...items].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const filtered = before ? sorted.filter(i => i.createdAt < before) : sorted;
  const page = filtered.slice(0, limit);
  const nextCursor = filtered.length > limit && page.length ? page[page.length - 1].createdAt : null;
  return { page, nextCursor };
}
function isBlocked(a: string, b: string) {
  return stores.blocks.some(x => (x.blockerId === a && x.blockedId === b) || (x.blockerId === b && x.blockedId === a));
}
function hiddenUserIds(uid: string) {
  const hidden = new Set<string>();
  for (const x of stores.blocks) {
    if (x.blockerId === uid) hidden.add(x.blockedId);
    else if (x.blockedId === uid) hidden.add(x.blockerId);
  }
  return hidden;
}
function userBrief(u: any) {
  return { userId: u.userId, username: u.username, displayName: u.displayName, photoURL: u.photoURL || '', isVerified: Boolean(u.isVerified), bio: u.bio || '' };
}
function prefsOf(user: any) { return { likes: true, comments: true, follows: true, messages: true, ...(user?.notificationPrefs || {}) }; }
function prefKeyFor(type: string) {
  if (type === 'like') return 'likes';
  if (type === 'comment' || type === 'reply') return 'comments';
  if (type === 'follow') return 'follows';
  return 'messages';
}
function liveOwner(item: any) {
  const u = stores.users.find(x => x.userId === item.ownerId);
  return u ? { ownerUsername: u.username, ownerDisplayName: u.displayName, ownerPhotoURL: u.photoURL || '', isVerified: Boolean(u.isVerified) } : {};
}
function decorate(item: any, type: 'posts' | 'reels', uid: string) {
  const key = type === 'posts' ? 'postId' : 'reelId';
  const ctype = type === 'posts' ? 'post' : 'reel';
  return {
    ...item, ...liveOwner(item),
    likeCount: stores.reactions.filter(r => r.contentId === item[key] && r.contentType === ctype).length,
    commentCount: stores.comments.filter(c => c.targetType === type && c.targetId === item[key]).length,
    isLiked: stores.reactions.some(r => r.userId === uid && r.contentId === item[key] && r.contentType === ctype),
    isFavorited: stores.favorites.some(f => f.userId === uid && f.contentId === item[key]),
    ownerIsFollowing: stores.follows.some(f => f.userId === uid && f.targetUserId === item.ownerId),
  };
}
const MEDIA_URL_RE = /^(?:https?:\/\/[^/]+)?\/api\/media\/([A-Za-z0-9_]+)$/;
const ALLOW_LEGACY_DATA_URLS = process.env.TSUKYO_ALLOW_DATA_URLS !== 'false';
function resolveMedia(url: string, user: any, folders: string[]): { ok: true; url: string; mediaType: 'image' | 'video' } | { ok: false; error: string } {
  const match = MEDIA_URL_RE.exec(url);
  if (match) {
    const rec = stores.media.find(x => x.mediaId === match[1]);
    if (!rec || rec.ownerId !== user.userId) return { ok: false, error: 'Media not found. Upload the file first.' };
    if (!folders.includes(rec.folder)) return { ok: false, error: 'This media cannot be used here.' };
    const isVideo = String(rec.contentType).startsWith('video/') || /\.(mp4|mov|webm|m4v|avi|mkv|3gp|ogv)$/i.test(rec.filename);
    return { ok: true, url: `/api/media/${rec.mediaId}`, mediaType: isVideo ? 'video' : 'image' };
  }
  if (ALLOW_LEGACY_DATA_URLS && url.startsWith('data:image/') && url.length <= 4_000_000) return { ok: true, url, mediaType: 'image' };
  return { ok: false, error: 'Media must be uploaded before publishing.' };
}
function deleteMediaByUrl(url: string) {
  const match = MEDIA_URL_RE.exec(url || '');
  if (!match) return;
  const idx = stores.media.findIndex(m => m.mediaId === match[1]);
  if (idx < 0) return;
  const rec = stores.media[idx];
  stores.media.splice(idx, 1);
  void fs.promises.rm(path.join(MEDIA_DIR, rec.storedName), { force: true }).catch(() => {});
  void persist('media');
}

// Login throttling (in memory, per IP + email).
const loginAttempts = new Map<string, { count: number; first: number }>();
function throttled(key: string) {
  const entry = loginAttempts.get(key);
  if (!entry || Date.now() - entry.first > 15 * 60 * 1000) return false;
  return entry.count >= 10;
}
function recordFailure(key: string) {
  const entry = loginAttempts.get(key);
  if (!entry || Date.now() - entry.first > 15 * 60 * 1000) loginAttempts.set(key, { count: 1, first: Date.now() });
  else entry.count += 1;
}

// ---------------------------------------------------------------------------
// Push notifications (Firebase Cloud Messaging HTTP v1, no extra dependencies)
// ---------------------------------------------------------------------------
function loadFcmAccount() {
  try {
    const raw = process.env.FCM_SERVICE_ACCOUNT_JSON || (process.env.FCM_SERVICE_ACCOUNT_FILE ? fs.readFileSync(process.env.FCM_SERVICE_ACCOUNT_FILE, 'utf8') : '');
    return raw ? JSON.parse(raw) : null;
  } catch (error) {
    console.error('FCM service account could not be loaded. Push notifications are disabled.');
    return null;
  }
}
const fcmAccount: any = loadFcmAccount();
const GOOGLE_TOKEN_URL = process.env.GOOGLE_TOKEN_URL || fcmAccount?.token_uri || 'https://oauth2.googleapis.com/token';
const FCM_BASE = process.env.FCM_API_BASE || 'https://fcm.googleapis.com';
let fcmAccessToken: { value: string; expiresAt: number } | null = null;
function b64u(value: string) { return Buffer.from(value).toString('base64url'); }
async function getFcmAccessToken() {
  if (fcmAccessToken && fcmAccessToken.expiresAt > Date.now() + 60_000) return fcmAccessToken.value;
  const iat = Math.floor(Date.now() / 1000);
  const header = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = b64u(JSON.stringify({ iss: fcmAccount.client_email, scope: 'https://www.googleapis.com/auth/firebase.messaging', aud: GOOGLE_TOKEN_URL, iat, exp: iat + 3600 }));
  const signature = crypto.createSign('RSA-SHA256').update(`${header}.${claim}`).sign(fcmAccount.private_key).toString('base64url');
  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${header}.${claim}.${signature}` }),
  });
  if (!response.ok) throw new Error(`FCM authentication failed (${response.status}).`);
  const json: any = await response.json();
  fcmAccessToken = { value: json.access_token, expiresAt: Date.now() + (Number(json.expires_in) || 3600) * 1000 };
  return fcmAccessToken.value;
}
async function sendPush(userId: string, data: Record<string, string>) {
  if (!fcmAccount) return;
  const devices = stores.devices.filter(d => d.userId === userId);
  if (!devices.length) return;
  let accessToken = '';
  try { accessToken = await getFcmAccessToken(); } catch (error) { console.error(String((error as Error).message)); return; }
  for (const device of devices) {
    try {
      const response = await fetch(`${FCM_BASE}/v1/projects/${fcmAccount.project_id}/messages:send`, {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: { token: device.token, data, android: { priority: 'HIGH' } } }),
      });
      if (!response.ok) {
        const text = await response.text();
        if (response.status === 404 || /UNREGISTERED/.test(text)) {
          stores.devices = stores.devices.filter(d => d.token !== device.token);
          void persist('devices');
        } else console.error('FCM send failed', response.status, text.slice(0, 200));
      }
    } catch (error) { console.error('FCM send error', String((error as Error).message)); }
  }
}

// ---------------------------------------------------------------------------
// Messaging helpers
// ---------------------------------------------------------------------------
function visibleMessages(conv: any, uid: string) {
  const joined = conv.memberJoinedAt?.[uid] || '';
  return stores.messages.filter(m => m.conversationId === conv.conversationId && m.createdAt >= joined);
}
function isReadBy(conv: any, m: any, uid: string) {
  return (m.readBy || []).includes(uid) || (!conv.isGroup && Boolean(m.isRead));
}
function unreadCountFor(conv: any, uid: string) {
  return visibleMessages(conv, uid).filter(m => m.senderId !== uid && m.messageType !== 'system' && !m.deleted && !isReadBy(conv, m, uid)).length;
}
function unreadSummary(uid: string) {
  let conversations = 0; let messages = 0;
  for (const conv of stores.conversations) {
    if (!conv.participantIds.includes(uid) || (conv.mutedBy || []).includes(uid)) continue;
    const count = unreadCountFor(conv, uid);
    if (count > 0) { conversations += 1; messages += count; }
  }
  return { unreadConversations: conversations, unreadMessages: messages };
}
function convView(conv: any, uid: string) {
  const details: Record<string, any> = {};
  for (const pid of conv.participantIds) {
    const u = stores.users.find(x => x.userId === pid);
    if (u) details[pid] = { displayName: u.displayName, username: u.username, photoURL: u.photoURL || '', isVerified: Boolean(u.isVerified) };
  }
  const { mutedBy, memberJoinedAt, ...rest } = conv;
  return { ...rest, isGroup: Boolean(conv.isGroup), participantDetails: details, unreadCount: unreadCountFor(conv, uid), muted: (mutedBy || []).includes(uid) };
}
function snippet(text: string, mediaURL?: string) { return text ? text.slice(0, 140) : (mediaURL ? 'Sent a photo' : 'New message'); }
function addSystemMessage(conv: any, text: string) {
  const message = { messageId: id('msg'), conversationId: conv.conversationId, senderId: 'system', senderUsername: 'Tsukyo', senderPhotoURL: '', text, messageType: 'system', isRead: true, readBy: [], createdAt: now() };
  stores.messages.push(message);
  conv.lastMessage = text; conv.lastMessageSenderId = 'system'; conv.updatedAt = message.createdAt;
  return message;
}
function notifyConversation(conv: any, ...uids: string[]) {
  for (const uid of new Set([...conv.participantIds, ...uids])) touchTopics(`conversations:${uid}`);
  touchTopics(`messages:${conv.conversationId}`);
}
function requireMember(req: Request, res: Response) {
  const uid = me(req).userId;
  const conv = stores.conversations.find(c => c.conversationId === req.params.conversationId || c.conversationId === req.params.groupId);
  if (!conv || !conv.participantIds.includes(uid)) { res.status(403).json({ error: 'Forbidden.' }); return null; }
  return conv;
}
function isAdmin(conv: any, uid: string) { return (conv.adminIds || []).includes(uid); }
function memberView(conv: any) {
  return conv.participantIds.map((pid: string) => {
    const u = stores.users.find(x => x.userId === pid);
    return u ? { ...userBrief(u), role: pid === conv.creatorId ? 'creator' : isAdmin(conv, pid) ? 'admin' : 'member', joinedAt: conv.memberJoinedAt?.[pid] || conv.createdAt } : null;
  }).filter(Boolean);
}
function deleteConversationData(conversationId: string) {
  stores.conversations = stores.conversations.filter(c => c.conversationId !== conversationId);
  for (const m of stores.messages.filter(m => m.conversationId === conversationId)) deleteMediaByUrl(m.mediaURL);
  stores.messages = stores.messages.filter(m => m.conversationId !== conversationId);
}
function removeMember(conv: any, uid: string) {
  conv.participantIds = conv.participantIds.filter((p: string) => p !== uid);
  conv.adminIds = (conv.adminIds || []).filter((p: string) => p !== uid);
  conv.mutedBy = (conv.mutedBy || []).filter((p: string) => p !== uid);
  if (conv.memberJoinedAt) delete conv.memberJoinedAt[uid];
  if (conv.creatorId === uid && conv.participantIds.length) {
    const successor = conv.adminIds[0] || conv.participantIds[0];
    conv.creatorId = successor;
    if (!conv.adminIds.includes(successor)) conv.adminIds.push(successor);
  }
}
async function persistChat() { await Promise.all([persist('conversations'), persist('messages')]); }

async function deleteAccountData(uid: string) {
  const ownPosts = stores.posts.filter(p => p.ownerId === uid).map(p => p.postId);
  const ownReels = stores.reels.filter(r => r.ownerId === uid).map(r => r.reelId);
  const ownedContent = new Set([...ownPosts, ...ownReels]);
  for (const item of [...stores.posts, ...stores.reels, ...stores.stories].filter(x => x.ownerId === uid)) deleteMediaByUrl(item.mediaURL);
  for (const m of stores.media.filter(m => m.ownerId === uid)) { void fs.promises.rm(path.join(MEDIA_DIR, m.storedName), { force: true }).catch(() => {}); }
  stores.media = stores.media.filter(m => m.ownerId !== uid);
  stores.posts = stores.posts.filter(p => p.ownerId !== uid);
  stores.reels = stores.reels.filter(r => r.ownerId !== uid);
  stores.stories = stores.stories.filter(s => s.ownerId !== uid);
  stores.comments = stores.comments.filter(c => c.authorId !== uid && !ownedContent.has(c.targetId));
  stores.reactions = stores.reactions.filter(r => r.userId !== uid && !ownedContent.has(r.contentId));
  stores.favorites = stores.favorites.filter(f => f.userId !== uid && !ownedContent.has(f.contentId));
  stores.follows = stores.follows.filter(f => f.userId !== uid && f.targetUserId !== uid);
  stores.blocks = stores.blocks.filter(b => b.blockerId !== uid && b.blockedId !== uid);
  stores.notifications = stores.notifications.filter(n => n.userId !== uid && n.senderId !== uid);
  stores.devices = stores.devices.filter(d => d.userId !== uid);
  stores.sessions = stores.sessions.filter(s => s.userId !== uid);
  stores.appLocks = stores.appLocks.filter(a => a.userId !== uid);
  for (const conv of [...stores.conversations].filter(c => c.participantIds.includes(uid))) {
    if (conv.isGroup && conv.participantIds.length > 1) { removeMember(conv, uid); addSystemMessage(conv, 'A member left the group.'); }
    else deleteConversationData(conv.conversationId);
  }
  stores.users = stores.users.filter(u => u.userId !== uid);
  await saveAll();
}

const sseClients = new Map<Response, string>();
function audienceFor(topic: string): string[] | null {
  const direct = /^(conversations|notifications):(.+)$/.exec(topic);
  if (direct) return [direct[2]];
  const chat = /^messages:(.+)$/.exec(topic);
  if (chat) {
    const conv = stores.conversations.find(c => c.conversationId === chat[1]);
    return conv ? conv.participantIds : [];
  }
  return null;
}
function broadcast(topic: string, payload: any = {}) {
  const audience = audienceFor(topic);
  const data = `event: update\ndata: ${JSON.stringify({ topic, ...payload })}\n\n`;
  for (const [client, uid] of sseClients) {
    if (audience && !audience.includes(uid)) continue;
    try { client.write(data); } catch { sseClients.delete(client); }
  }
}
function touchTopics(...topics: string[]) { for (const topic of topics) broadcast(topic); }

function ownerIdOfContent(type: 'posts' | 'reels', contentId: string) {
  const item = stores[type].find(x => x[type === 'posts' ? 'postId' : 'reelId'] === contentId);
  return item?.ownerId || item?.userId || null;
}
function addNotification(userId: string, sender: any, type: 'like'|'comment'|'reply'|'follow', message: string, targetId?: string) {
  if (!userId || !sender || userId === sender.userId) return;
  const recipient = stores.users.find(u => u.userId === userId);
  if (!recipient || !prefsOf(recipient)[prefKeyFor(type)] || isBlocked(userId, sender.userId)) return;
  const notificationId = id('notification');
  stores.notifications.push({
    notificationId, userId, senderId: sender.userId,
    senderUsername: sender.username, senderPhotoURL: sender.photoURL || '', type,
    message, targetId, read: false, createdAt: now(),
  });
  void persist('notifications');
  touchTopics(`notifications:${userId}`);
  void sendPush(userId, { type, notificationId, title: 'Tsukyo', body: message, targetId: targetId || '', senderId: sender.userId });
}

async function saveAll() {
  await Promise.all((Object.keys(files) as (keyof typeof files)[]).map(k => persist(k)));
}

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  const origin = process.env.CORS_ORIGIN || req.headers.origin || '';
  if (!IS_PRODUCTION || origin === process.env.CORS_ORIGIN) {
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (process.env.CORS_ORIGIN) {
    res.setHeader('Access-Control-Allow-Origin', process.env.CORS_ORIGIN);
  }
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '8mb' }));

app.get('/api/health', (_req, res) => res.json({ status: 'ok', time: now(), backend: 'custom' }));

// Authentication
app.post('/api/auth/register', async (req, res) => {
  const { email, password, username, displayName } = req.body || {};
  const normalizedEmail = normalizeEmail(email);
  const cleanUsername = sanitizeUsername(username);
  if (!normalizedEmail || !/^\S+@\S+\.\S+$/.test(normalizedEmail)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (!cleanUsername || cleanUsername.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  if (!validateString(displayName, 80)) return res.status(400).json({ error: 'Display name is invalid.' });
  if (stores.users.some(u => u.email === normalizedEmail)) return res.status(409).json({ error: 'An account with this email already exists.' });
  if (stores.users.some(u => u.username === cleanUsername)) return res.status(409).json({ error: 'That username is already taken.' });
  const { hash, salt } = passwordHash(password);
  const userId = id('user');
  const profile = {
    userId, email: normalizedEmail, displayName: String(displayName).trim(), username: cleanUsername,
    photoURL: '', bio: '', website: '', isVerified: false, theme: 'gray_white', notificationPrefs: { likes: true, comments: true, follows: true, messages: true },
    appLockHash: '', appLockEnabled: false,     createdAt: now(), passwordHash: hash, passwordSalt: salt,
  };
  stores.users.push(profile);
  await persist('users');
  const token = createSession(userId);
  return res.status(201).json({ token, user: publicUser(profile, true) });
});

app.post('/api/auth/login', async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = req.body?.password;
  const throttleKey = `${req.ip}|${email}`;
  if (throttled(throttleKey)) return res.status(429).json({ error: 'Too many sign-in attempts. Try again in a few minutes.' });
  const user = stores.users.find(u => u.email === email);
  if (!user || typeof password !== 'string' || !user.passwordHash || !user.passwordSalt) { recordFailure(throttleKey); return res.status(401).json({ error: 'Invalid email or password.' }); }
  const { hash } = passwordHash(password, user.passwordSalt);
  if (!safeEqualHex(hash, user.passwordHash)) { recordFailure(throttleKey); return res.status(401).json({ error: 'Invalid email or password.' }); }
  loginAttempts.delete(throttleKey);
  const token = createSession(user.userId);
  return res.json({ token, user: publicUser(user, true) });
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  const token = getToken(req);
  stores.sessions = stores.sessions.filter(s => s.tokenHash !== sessionDigest(token));
  const deviceToken = String(req.body?.deviceToken || '');
  if (deviceToken) { stores.devices = stores.devices.filter(d => d.token !== deviceToken); await persist('devices'); }
  await persist('sessions');
  res.json({ ok: true });
});
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: publicUser((req as any).user, true) }));
app.post('/api/auth/reset-password', async (_req, res) => {
  // No mail provider is configured. Do not reveal whether an account exists.
  res.json({ ok: true, message: 'If that email belongs to an account, password reset instructions can be issued by the account administrator.' });
});

// Profile / users
app.get('/api/users/search', requireAuth, (req, res) => {
  const viewer = me(req);
  const q = String(req.query.q || '').trim().toLowerCase().replace(/^@/, '');
  const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 30));
  const offset = Math.max(0, Number(req.query.offset) || 0);
  const hidden = hiddenUserIds(viewer.userId);
  const matches = stores.users
    .filter(u => !hidden.has(u.userId) && (!q || u.username.toLowerCase().includes(q) || String(u.displayName).toLowerCase().includes(q)))
    .sort((a, b) => Number(b.username.toLowerCase().startsWith(q)) - Number(a.username.toLowerCase().startsWith(q)) || a.username.localeCompare(b.username));
  const users = matches.slice(offset, offset + limit).map(u => publicUser(u));
  res.json({ users, nextOffset: offset + limit < matches.length ? offset + limit : null });
});
app.get('/api/users/:userId', requireAuth, (req, res) => {
  const viewer = me(req);
  const user = stores.users.find(u => u.userId === req.params.userId);
  if (!user || stores.blocks.some(b => b.blockerId === user.userId && b.blockedId === viewer.userId)) return res.status(404).json({ error: 'User not found.' });
  res.json({
    user: publicUser(user, user.userId === viewer.userId),
    isFollowing: stores.follows.some(f => f.userId === viewer.userId && f.targetUserId === user.userId),
    isFollowedBy: stores.follows.some(f => f.userId === user.userId && f.targetUserId === viewer.userId),
    isBlocked: stores.blocks.some(b => b.blockerId === viewer.userId && b.blockedId === user.userId),
  });
});
app.patch('/api/users/:userId', requireAuth, async (req, res) => {
  const actor = me(req);
  if (actor.userId !== req.params.userId) return res.status(403).json({ error: 'You can only edit your own profile.' });
  const user = stores.users.find(u => u.userId === actor.userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const body = req.body || {};
  if (body.username !== undefined) {
    const username = sanitizeUsername(body.username);
    if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters.' });
    if (stores.users.some(u => u.username === username && u.userId !== user.userId)) return res.status(409).json({ error: 'That username is already taken.' });
    user.username = username;
  }
  if (body.displayName !== undefined) {
    if (typeof body.displayName !== 'string' || !body.displayName.trim() || body.displayName.length > 80) return res.status(400).json({ error: 'Display name must be 1 to 80 characters.' });
    user.displayName = body.displayName.trim();
  }
  if (body.bio !== undefined) {
    if (typeof body.bio !== 'string' || body.bio.length > 500) return res.status(400).json({ error: 'Bio must be 500 characters or fewer.' });
    user.bio = body.bio;
  }
  if (body.website !== undefined) {
    if (typeof body.website !== 'string' || body.website.length > 200) return res.status(400).json({ error: 'Website must be 200 characters or fewer.' });
    user.website = body.website.trim();
  }
  if (body.theme !== undefined && typeof body.theme === 'string' && body.theme.length <= 50) user.theme = body.theme;
  if (body.photoURL !== undefined) {
    const photo = String(body.photoURL);
    if (photo && !MEDIA_URL_RE.test(photo) && !(ALLOW_LEGACY_DATA_URLS && photo.startsWith('data:image/') && photo.length <= 4_000_000)) return res.status(400).json({ error: 'Profile photo must be an uploaded image.' });
    user.photoURL = photo;
  }
  user.updatedAt = now();
  await persist('users');
  res.json({ user: publicUser(user, true) });
  touchTopics(`profile:${user.userId}`, 'feed', 'reels');
});
app.patch('/api/users/me/preferences', requireAuth, async (req, res) => {
  const user = me(req);
  const current = prefsOf(user);
  for (const key of ['likes', 'comments', 'follows', 'messages'] as const) {
    if (req.body?.[key] !== undefined) {
      if (typeof req.body[key] !== 'boolean') return res.status(400).json({ error: 'Notification preferences must be true or false.' });
      current[key] = req.body[key];
    }
  }
  user.notificationPrefs = current;
  await persist('users');
  res.json({ notificationPrefs: current });
});
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const user = me(req);
  const { currentPassword, newPassword } = req.body || {};
  if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') return res.status(400).json({ error: 'Current and new passwords are required.' });
  if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const { hash } = passwordHash(currentPassword, user.passwordSalt);
  if (!safeEqualHex(hash, user.passwordHash)) return res.status(403).json({ error: 'The current password is incorrect.' });
  const next = passwordHash(newPassword);
  user.passwordHash = next.hash; user.passwordSalt = next.salt;
  const keep = sessionDigest(getToken(req));
  stores.sessions = stores.sessions.filter(s => s.userId !== user.userId || s.tokenHash === keep);
  await Promise.all([persist('users'), persist('sessions')]);
  res.json({ ok: true });
});
app.delete('/api/users/me', requireAuth, async (req, res) => {
  const user = me(req);
  const password = req.body?.password;
  if (typeof password !== 'string') return res.status(400).json({ error: 'Enter your password to delete your account.' });
  const { hash } = passwordHash(password, user.passwordSalt);
  if (!safeEqualHex(hash, user.passwordHash)) return res.status(403).json({ error: 'The password is incorrect.' });
  await deleteAccountData(user.userId);
  touchTopics('feed', 'reels', 'stories');
  res.json({ ok: true });
});
app.post('/api/devices', requireAuth, async (req, res) => {
  const user = me(req);
  const token = String(req.body?.token || '');
  if (token.length < 20 || token.length > 4096) return res.status(400).json({ error: 'Invalid device token.' });
  stores.devices = stores.devices.filter(d => d.token !== token);
  stores.devices.push({ userId: user.userId, token, platform: 'android', createdAt: now() });
  await persist('devices');
  res.json({ ok: true, pushEnabled: Boolean(fcmAccount) });
});
app.delete('/api/devices', requireAuth, async (req, res) => {
  const user = me(req);
  const token = String(req.body?.token || '');
  stores.devices = stores.devices.filter(d => !(d.token === token && d.userId === user.userId));
  await persist('devices');
  res.json({ ok: true });
});

// Blocking and reporting
app.get('/api/blocks', requireAuth, (req, res) => {
  const uid = me(req).userId;
  const users = stores.blocks.filter(b => b.blockerId === uid).map(b => stores.users.find(u => u.userId === b.blockedId)).filter(Boolean).map(userBrief);
  res.json({ users });
});
app.post('/api/users/:userId/block', requireAuth, async (req, res) => {
  const user = me(req);
  const target = stores.users.find(u => u.userId === req.params.userId);
  if (!target) return res.status(404).json({ error: 'User not found.' });
  if (target.userId === user.userId) return res.status(400).json({ error: 'You cannot block yourself.' });
  if (!stores.blocks.some(b => b.blockerId === user.userId && b.blockedId === target.userId)) {
    stores.blocks.push({ blockerId: user.userId, blockedId: target.userId, createdAt: now() });
    stores.follows = stores.follows.filter(f => !((f.userId === user.userId && f.targetUserId === target.userId) || (f.userId === target.userId && f.targetUserId === user.userId)));
    await Promise.all([persist('blocks'), persist('follows')]);
    touchTopics('feed', 'reels', 'stories', `profile:${user.userId}`, `profile:${target.userId}`);
  }
  res.json({ blocked: true });
});
app.delete('/api/users/:userId/block', requireAuth, async (req, res) => {
  const user = me(req);
  stores.blocks = stores.blocks.filter(b => !(b.blockerId === user.userId && b.blockedId === req.params.userId));
  await persist('blocks');
  touchTopics('feed', 'reels', 'stories');
  res.json({ blocked: false });
});
app.post('/api/reports', requireAuth, async (req, res) => {
  const user = me(req);
  const { targetType, targetId, reason, details } = req.body || {};
  const exists: Record<string, () => boolean> = {
    user: () => stores.users.some(u => u.userId === targetId),
    post: () => stores.posts.some(p => p.postId === targetId),
    reel: () => stores.reels.some(r => r.reelId === targetId),
    comment: () => stores.comments.some(c => c.commentId === targetId),
    message: () => stores.messages.some(m => m.messageId === targetId && stores.conversations.some(c => c.conversationId === m.conversationId && c.participantIds.includes(user.userId))),
  };
  if (!exists[targetType] || typeof targetId !== 'string') return res.status(400).json({ error: 'Invalid report target.' });
  if (!exists[targetType]()) return res.status(404).json({ error: 'The reported content could not be found.' });
  if (typeof reason !== 'string' || !reason.trim() || reason.length > 100) return res.status(400).json({ error: 'Select a reason for the report.' });
  if (details !== undefined && (typeof details !== 'string' || details.length > 1000)) return res.status(400).json({ error: 'Details must be 1000 characters or fewer.' });
  if (!stores.reports.some(r => r.reporterId === user.userId && r.targetType === targetType && r.targetId === targetId)) {
    stores.reports.push({ reportId: id('report'), reporterId: user.userId, targetType, targetId, reason: reason.trim(), details: String(details || ''), status: 'open', createdAt: now() });
    await persist('reports');
  }
  res.status(201).json({ ok: true });
});

// App lock
app.get('/api/users/:userId/app-lock', requireAuth, (req, res) => {
  if ((req as any).user.userId !== req.params.userId) return res.status(403).json({ error: 'Forbidden.' });
  const item = stores.appLocks.find(x => x.userId === req.params.userId);
  res.json({ enabled: Boolean(item?.enabled), configured: Boolean(item?.enabled && item?.pinHash) });
});
app.put('/api/users/:userId/app-lock', requireAuth, async (req, res) => {
  const actor = (req as any).user;
  if (actor.userId !== req.params.userId) return res.status(403).json({ error: 'Forbidden.' });
  const pin = String(req.body?.pin || '');
  if (!/^\d{4,12}$/.test(pin)) return res.status(400).json({ error: 'PIN must contain 4 to 12 digits.' });
  const { hash, salt } = passwordHash(pin);
  const existing = stores.appLocks.find(x => x.userId === actor.userId);
  const record = { userId: actor.userId, enabled: true, pinHash: hash, pinSalt: salt, updatedAt: now() };
  if (existing) Object.assign(existing, record); else stores.appLocks.push(record);
  const profile = stores.users.find(u => u.userId === actor.userId);
  if (profile) { profile.appLockEnabled = true; profile.appLockHash = 'server-managed'; await persist('users'); }
  await persist('appLocks');
  res.json({ configured: true });
});
app.post('/api/users/:userId/app-lock/verify', requireAuth, (req, res) => {
  const actor = (req as any).user;
  if (actor.userId !== req.params.userId) return res.status(403).json({ error: 'Forbidden.' });
  const record = stores.appLocks.find(x => x.userId === actor.userId && x.enabled);
  if (!record) return res.json({ ok: true, configured: false });
  const { hash } = passwordHash(String(req.body?.pin || ''), record.pinSalt);
  res.json({ ok: safeEqualHex(hash, record.pinHash), configured: true });
});
app.delete('/api/users/:userId/app-lock', requireAuth, async (req, res) => {
  const actor = (req as any).user;
  if (actor.userId !== req.params.userId) return res.status(403).json({ error: 'Forbidden.' });
  const record = stores.appLocks.find(x => x.userId === actor.userId && x.enabled);
  if (record && req.body?.pin) {
    const { hash } = passwordHash(String(req.body.pin), record.pinSalt);
    if (!safeEqualHex(hash, record.pinHash)) return res.status(403).json({ error: 'Incorrect PIN.' });
  }
  stores.appLocks = stores.appLocks.filter(x => x.userId !== actor.userId);
  const profile = stores.users.find(u => u.userId === actor.userId);
  if (profile) { profile.appLockEnabled = false; profile.appLockHash = ''; await persist('users'); }
  await persist('appLocks');
  res.json({ configured: false });
});

// Feed/content
app.get('/api/feed', requireAuth, (req, res) => {
  const uid = me(req).userId; const { limit, before } = pageParams(req);
  const hidden = hiddenUserIds(uid);
  let source = stores.posts.filter(p => !hidden.has(p.ownerId));
  if (req.query.scope === 'following') {
    const following = new Set(stores.follows.filter(f => f.userId === uid).map(f => f.targetUserId));
    following.add(uid);
    source = source.filter(p => following.has(p.ownerId));
  }
  const { page, nextCursor } = paginate(source, limit, before);
  res.json({ posts: page.map(p => decorate(p, 'posts', uid)), nextCursor });
});
app.get('/api/posts/:postId', requireAuth, (req, res) => {
  const uid = me(req).userId;
  const post = stores.posts.find(p => p.postId === req.params.postId);
  if (!post || hiddenUserIds(uid).has(post.ownerId)) return res.status(404).json({ error: 'Post not found.' });
  res.json({ post: decorate(post, 'posts', uid) });
});
app.get('/api/search', requireAuth, (req, res) => {
  const uid = me(req).userId;
  const type = req.query.type === 'reels' ? 'reels' : 'posts';
  const q = String(req.query.q || '').trim().toLowerCase();
  const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 30));
  const offset = Math.max(0, Number(req.query.offset) || 0);
  const hidden = hiddenUserIds(uid);
  const matches = stores[type]
    .filter(x => !hidden.has(x.ownerId) && (!q || String(x.caption || '').toLowerCase().includes(q)))
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  res.json({ [type]: matches.slice(offset, offset + limit).map(x => decorate(x, type, uid)), nextOffset: offset + limit < matches.length ? offset + limit : null });
});
app.get('/api/stories', requireAuth, (req, res) => {
  const uid = me(req).userId; const current = Date.now(); const hidden = hiddenUserIds(uid);
  const stories = stores.stories
    .filter(s => (!s.expiresAt || new Date(s.expiresAt).getTime() > current) && !hidden.has(s.ownerId))
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 100)
    .map(s => {
      const { viewers, ...rest } = s;
      return { ...rest, ...liveOwner(s), viewed: (viewers || []).some((v: any) => v.userId === uid), viewerCount: s.ownerId === uid ? (viewers || []).length : undefined };
    });
  res.json({ stories });
});
app.get('/api/users/:userId/posts', requireAuth, (req, res) => {
  const uid = me(req).userId;
  if (hiddenUserIds(uid).has(req.params.userId)) return res.json({ posts: [], nextCursor: null });
  const { limit, before } = pageParams(req, 60);
  const { page, nextCursor } = paginate(stores.posts.filter(p => p.ownerId === req.params.userId), limit, before);
  res.json({ posts: page.map(p => decorate(p, 'posts', uid)), nextCursor });
});
app.get('/api/users/:userId/reels', requireAuth, (req, res) => {
  const uid = me(req).userId;
  if (hiddenUserIds(uid).has(req.params.userId)) return res.json({ reels: [], nextCursor: null });
  const { limit, before } = pageParams(req, 60);
  const { page, nextCursor } = paginate(stores.reels.filter(r => r.ownerId === req.params.userId), limit, before);
  res.json({ reels: page.map(r => decorate(r, 'reels', uid)), nextCursor });
});

app.post('/api/posts', requireAuth, async (req, res) => {
  const user = me(req); const body = req.body || {};
  if (!validateString(body.caption || '', 2200)) return res.status(400).json({ error: 'Caption must be 2200 characters or fewer.' });
  const media = resolveMedia(String(body.mediaURL || ''), user, ['posts']);
  if (!media.ok) return res.status(400).json({ error: media.error });
  const post = {
    postId: id('post'), ownerId: user.userId, ownerUsername: user.username, ownerDisplayName: user.displayName,
    ownerPhotoURL: user.photoURL || '', caption: String(body.caption || '').trim(), location: String(body.location || '').slice(0, 100),
    mediaURL: media.url, mediaType: media.mediaType, isVerified: Boolean(user.isVerified), likeCount: 0, commentCount: 0, createdAt: now(),
  };
  stores.posts.push(post);
  await persist('posts');
  touchTopics('feed', `profile:${user.userId}`);
  res.status(201).json({ post: decorate(post, 'posts', user.userId) });
});
app.patch('/api/posts/:postId', requireAuth, async (req, res) => {
  const user = me(req); const post = stores.posts.find(p => p.postId === req.params.postId);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  if (post.ownerId !== user.userId) return res.status(403).json({ error: 'Only the owner can edit this post.' });
  if (typeof req.body?.caption !== 'string' || req.body.caption.length > 2200) return res.status(400).json({ error: 'Caption must be 2200 characters or fewer.' });
  post.caption = req.body.caption.trim(); post.updatedAt = now();
  await persist('posts'); touchTopics('feed');
  res.json({ post: decorate(post, 'posts', user.userId) });
});
function removeContent(type: 'posts' | 'reels', item: any) {
  const key = type === 'posts' ? 'postId' : 'reelId';
  stores[type] = stores[type].filter(x => x !== item);
  stores.comments = stores.comments.filter(c => !(c.targetType === type && c.targetId === item[key]));
  stores.reactions = stores.reactions.filter(r => r.contentId !== item[key]);
  stores.favorites = stores.favorites.filter(f => f.contentId !== item[key]);
  stores.notifications = stores.notifications.filter(n => n.targetId !== item[key]);
  deleteMediaByUrl(item.mediaURL);
}
async function persistContentRemoval(type: 'posts' | 'reels') {
  await Promise.all([persist(type), persist('comments'), persist('reactions'), persist('favorites'), persist('notifications')]);
}
app.delete('/api/posts/:postId', requireAuth, async (req, res) => {
  const user = me(req); const post = stores.posts.find(p => p.postId === req.params.postId);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  if (post.ownerId !== user.userId) return res.status(403).json({ error: 'Only the owner can delete this post.' });
  removeContent('posts', post); await persistContentRemoval('posts');
  touchTopics('feed', `profile:${user.userId}`); res.json({ ok: true });
});
app.post('/api/posts/:postId/like', requireAuth, async (req, res) => toggleLike(req, res, 'posts', req.params.postId));

app.post('/api/stories', requireAuth, async (req, res) => {
  const user = me(req); const body = req.body || {};
  const media = resolveMedia(String(body.mediaURL || ''), user, ['stories']);
  if (!media.ok) return res.status(400).json({ error: media.error });
  if (!validateString(body.caption || '', 500) || !validateString(body.overlayText || '', 200)) return res.status(400).json({ error: 'Story text is too long.' });
  const created = Date.now();
  const story = {
    storyId: id('story'), ownerId: user.userId, ownerUsername: user.username, ownerDisplayName: user.displayName,
    ownerPhotoURL: user.photoURL || '', mediaURL: media.url, mediaType: media.mediaType, caption: String(body.caption || ''),
    overlayText: String(body.overlayText || ''), isVerified: Boolean(user.isVerified), viewers: [],
    createdAt: new Date(created).toISOString(), expiresAt: new Date(created + 86400000).toISOString(),
  };
  stores.stories.push(story); await persist('stories'); touchTopics('stories');
  const { viewers, ...out } = story; res.status(201).json({ story: out });
});
app.post('/api/stories/:storyId/view', requireAuth, async (req, res) => {
  const user = me(req); const story = stores.stories.find(s => s.storyId === req.params.storyId);
  if (!story || hiddenUserIds(user.userId).has(story.ownerId)) return res.status(404).json({ error: 'Story not found.' });
  if (story.ownerId !== user.userId && !(story.viewers || []).some((v: any) => v.userId === user.userId)) {
    story.viewers = [...(story.viewers || []), { userId: user.userId, viewedAt: now() }]; await persist('stories');
  }
  res.json({ ok: true });
});
app.get('/api/stories/:storyId/viewers', requireAuth, (req, res) => {
  const user = me(req); const story = stores.stories.find(s => s.storyId === req.params.storyId);
  if (!story) return res.status(404).json({ error: 'Story not found.' });
  if (story.ownerId !== user.userId) return res.status(403).json({ error: 'Only the owner can see story viewers.' });
  const viewers = (story.viewers || []).map((v: any) => { const u = stores.users.find(x => x.userId === v.userId); return u ? { ...userBrief(u), viewedAt: v.viewedAt } : null; }).filter(Boolean);
  res.json({ viewers });
});
app.delete('/api/stories/:storyId', requireAuth, async (req, res) => {
  const user = me(req); const item = stores.stories.find(s => s.storyId === req.params.storyId);
  if (!item) return res.status(404).json({ error: 'Story not found.' });
  if (item.ownerId !== user.userId) return res.status(403).json({ error: 'Only the owner can delete this story.' });
  stores.stories = stores.stories.filter(s => s !== item); deleteMediaByUrl(item.mediaURL);
  await persist('stories'); touchTopics('stories'); res.json({ ok: true });
});

app.get('/api/reels', requireAuth, (req, res) => {
  const uid = me(req).userId; const { limit, before } = pageParams(req); const hidden = hiddenUserIds(uid);
  const { page, nextCursor } = paginate(stores.reels.filter(r => !hidden.has(r.ownerId)), limit, before);
  res.json({ reels: page.map(r => decorate(r, 'reels', uid)), nextCursor });
});
async function toggleLike(req: Request, res: Response, type: 'posts' | 'reels', contentId: string) {
  const user = me(req); const key = `${type}:${contentId}:${user.userId}`;
  const keyName = type === 'posts' ? 'postId' : 'reelId'; const ctype = type === 'posts' ? 'post' : 'reel';
  const item = stores[type].find(x => x[keyName] === contentId);
  if (!item || hiddenUserIds(user.userId).has(item.ownerId)) return res.status(404).json({ error: 'Content not found.' });
  const idx = stores.reactions.findIndex((x: any) => x.key === key);
  let liked = false;
  if (idx >= 0) stores.reactions.splice(idx, 1);
  else {
    liked = true;
    stores.reactions.push({ key, userId: user.userId, contentId, contentType: ctype, createdAt: now() });
    addNotification(item.ownerId, user, 'like', `@${user.username} liked your ${type === 'posts' ? 'post' : 'Reel'}.`, contentId);
  }
  await persist('reactions');
  touchTopics(type === 'posts' ? 'feed' : 'reels');
  res.json({ liked, likeCount: stores.reactions.filter(r => r.contentId === contentId && r.contentType === ctype).length });
}
app.post('/api/reels/:reelId/like', requireAuth, async (req, res) => toggleLike(req, res, 'reels', req.params.reelId));
app.post('/api/reels', requireAuth, async (req, res) => {
  const user = me(req); const body = req.body || {};
  const media = resolveMedia(String(body.mediaURL || ''), user, ['reels']);
  if (!media.ok) return res.status(400).json({ error: media.error });
  if (media.mediaType !== 'video') return res.status(400).json({ error: 'A Reel must be a video.' });
  if (!validateString(body.caption || '', 2200) || !validateString(body.audioTitle || '', 100)) return res.status(400).json({ error: 'Invalid Reel data.' });
  let coverURL = '';
  if (body.coverURL) {
    const cover = resolveMedia(String(body.coverURL), user, ['reels', 'posts']);
    if (!cover.ok || cover.mediaType !== 'image') return res.status(400).json({ error: 'The cover must be an uploaded image.' });
    coverURL = cover.url;
  }
  const reel = {
    reelId: id('reel'), ownerId: user.userId, ownerUsername: user.username, ownerDisplayName: user.displayName, ownerPhotoURL: user.photoURL || '',
    caption: String(body.caption || '').trim(), mediaURL: media.url, coverURL, audioTitle: String(body.audioTitle || '').trim() || 'Original audio',
    isVerified: Boolean(user.isVerified), likeCount: 0, commentCount: 0, createdAt: now(),
  };
  stores.reels.push(reel); await persist('reels'); touchTopics('reels', `profile:${user.userId}`);
  res.status(201).json({ reel: decorate(reel, 'reels', user.userId) });
});
app.delete('/api/reels/:reelId', requireAuth, async (req, res) => {
  const user = me(req); const reel = stores.reels.find(r => r.reelId === req.params.reelId);
  if (!reel) return res.status(404).json({ error: 'Reel not found.' });
  if (reel.ownerId !== user.userId) return res.status(403).json({ error: 'Only the owner can delete this Reel.' });
  removeContent('reels', reel); await persistContentRemoval('reels');
  touchTopics('reels', `profile:${user.userId}`); res.json({ ok: true });
});
app.get('/api/reels/:reelId', requireAuth, (req, res) => {
  const uid = me(req).userId; const reel = stores.reels.find(r => r.reelId === req.params.reelId);
  if (!reel || hiddenUserIds(uid).has(reel.ownerId)) return res.status(404).json({ error: 'Reel not found.' });
  res.json({ reel: decorate(reel, 'reels', uid) });
});

// Social graph
app.get('/api/users/:userId/followers', requireAuth, (req, res) => {
  const hidden = hiddenUserIds(me(req).userId);
  const ids = stores.follows.filter(f => f.targetUserId === req.params.userId && !hidden.has(f.userId)).map(f => f.userId);
  res.json({ userIds: ids, users: ids.map(i => stores.users.find(u => u.userId === i)).filter(Boolean).map(userBrief) });
});
app.get('/api/users/:userId/following', requireAuth, (req, res) => {
  const hidden = hiddenUserIds(me(req).userId);
  const ids = stores.follows.filter(f => f.userId === req.params.userId && !hidden.has(f.targetUserId)).map(f => f.targetUserId);
  res.json({ userIds: ids, users: ids.map(i => stores.users.find(u => u.userId === i)).filter(Boolean).map(userBrief) });
});
app.get('/api/users/:userId/following/:targetUserId', requireAuth, (req, res) => res.json({ following: stores.follows.some(f => f.userId === req.params.userId && f.targetUserId === req.params.targetUserId) }));
app.post('/api/users/:targetUserId/follow', requireAuth, async (req, res) => {
  const user = me(req); const target = stores.users.find(u => u.userId === req.params.targetUserId);
  if (!target) return res.status(404).json({ error: 'User not found.' });
  if (target.userId === user.userId) return res.status(400).json({ error: 'You cannot follow yourself.' });
  if (isBlocked(user.userId, target.userId)) return res.status(403).json({ error: 'You cannot follow this account.' });
  if (!stores.follows.some(f => f.userId === user.userId && f.targetUserId === target.userId)) {
    stores.follows.push({ userId: user.userId, targetUserId: target.userId, createdAt: now() });
    await persist('follows');
    addNotification(target.userId, user, 'follow', `@${user.username} started following you.`);
    touchTopics(`profile:${user.userId}`, `profile:${target.userId}`, 'feed');
  }
  res.json({ following: true, followerCount: stores.follows.filter(f => f.targetUserId === target.userId).length });
});
app.delete('/api/users/:targetUserId/follow', requireAuth, async (req, res) => {
  const user = me(req); const target = stores.users.find(u => u.userId === req.params.targetUserId);
  if (!target) return res.status(404).json({ error: 'User not found.' });
  const before = stores.follows.length;
  stores.follows = stores.follows.filter(f => !(f.userId === user.userId && f.targetUserId === target.userId));
  if (stores.follows.length !== before) { await persist('follows'); touchTopics(`profile:${user.userId}`, `profile:${target.userId}`, 'feed'); }
  res.json({ following: false, followerCount: stores.follows.filter(f => f.targetUserId === target.userId).length });
});

// Favorites
app.get('/api/favorites', requireAuth,(req,res)=>res.json({favorites:stores.favorites.filter(f=>f.userId===(req as any).user.userId)}));
app.get('/api/favorites/:contentId', requireAuth,(req,res)=>res.json({favorited:stores.favorites.some(f=>f.userId===(req as any).user.userId&&f.contentId===req.params.contentId)}));
app.post('/api/favorites/:contentId', requireAuth, async(req,res)=>{const user=(req as any).user;const {contentType,contentData}=req.body||{};const idx=stores.favorites.findIndex(f=>f.userId===user.userId&&f.contentId===req.params.contentId);if(idx>=0){stores.favorites.splice(idx,1);await persist('favorites');return res.json({favorited:false});}if(!['post','reel'].includes(contentType)||!contentData)return res.status(400).json({error:'Invalid favorite data.'});stores.favorites.push({userId:user.userId,contentId:req.params.contentId,contentType,contentData,savedAt:now()});await persist('favorites');res.json({favorited:true});});

// Comments
app.get('/api/:targetType/:targetId/comments', requireAuth, (req, res) => {
  if (!['posts', 'reels'].includes(req.params.targetType)) return res.status(400).json({ error: 'Invalid target.' });
  const hidden = hiddenUserIds(me(req).userId);
  const comments = stores.comments
    .filter(c => c.targetType === req.params.targetType && c.targetId === req.params.targetId && !hidden.has(c.authorId))
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
    .map(c => { const u = stores.users.find(x => x.userId === c.authorId); return u ? { ...c, authorUsername: u.username, authorDisplayName: u.displayName, authorPhotoURL: u.photoURL || '', isVerified: Boolean(u.isVerified) } : c; });
  res.json({ comments });
});
app.post('/api/:targetType/:targetId/comments', requireAuth, async (req, res) => {
  const targetType = req.params.targetType as 'posts' | 'reels';
  if (!['posts', 'reels'].includes(targetType)) return res.status(400).json({ error: 'Invalid target.' });
  const user = me(req); const text = String(req.body?.text || '').trim();
  if (!text || text.length > 2000) return res.status(400).json({ error: 'A comment must be between 1 and 2000 characters.' });
  const key = targetType === 'posts' ? 'postId' : 'reelId';
  const target = stores[targetType].find(x => x[key] === req.params.targetId);
  if (!target || hiddenUserIds(user.userId).has(target.ownerId)) return res.status(404).json({ error: 'Content not found.' });
  let parent: any = null;
  if (req.body?.parentId) {
    parent = stores.comments.find(c => c.commentId === req.body.parentId && c.targetId === req.params.targetId && c.targetType === targetType);
    if (!parent) return res.status(404).json({ error: 'The comment you are replying to no longer exists.' });
    if (parent.parentId) parent = stores.comments.find(c => c.commentId === parent.parentId) || parent;
  }
  const comment = { commentId: id('comment'), targetId: req.params.targetId, targetType, authorId: user.userId, authorUsername: user.username, authorDisplayName: user.displayName, authorPhotoURL: user.photoURL || '', isVerified: Boolean(user.isVerified), text, ...(parent ? { parentId: parent.commentId } : {}), createdAt: now() };
  stores.comments.push(comment); await persist('comments');
  addNotification(target.ownerId, user, 'comment', `@${user.username} commented on your ${targetType === 'posts' ? 'post' : 'Reel'}.`, req.params.targetId);
  if (parent) addNotification(parent.authorId, user, 'reply', `@${user.username} replied to your comment.`, req.params.targetId);
  touchTopics(`comments:${targetType}:${req.params.targetId}`, targetType === 'posts' ? 'feed' : 'reels');
  res.status(201).json({ comment, commentCount: stores.comments.filter(c => c.targetType === targetType && c.targetId === req.params.targetId).length });
});
app.delete('/api/:targetType/:targetId/comments/:commentId', requireAuth, async (req, res) => {
  const user = me(req);
  if (!['posts', 'reels'].includes(req.params.targetType)) return res.status(400).json({ error: 'Invalid target.' });
  const comment = stores.comments.find(c => c.commentId === req.params.commentId && c.targetId === req.params.targetId);
  if (!comment) return res.status(404).json({ error: 'Comment not found.' });
  const key = req.params.targetType === 'posts' ? 'postId' : 'reelId';
  const target = stores[req.params.targetType].find(x => x[key] === req.params.targetId);
  if (comment.authorId !== user.userId && target?.ownerId !== user.userId) return res.status(403).json({ error: 'You cannot delete this comment.' });
  stores.comments = stores.comments.filter(c => c.commentId !== comment.commentId && c.parentId !== comment.commentId);
  await persist('comments');
  touchTopics(`comments:${req.params.targetType}:${req.params.targetId}`, req.params.targetType === 'posts' ? 'feed' : 'reels');
  res.json({ ok: true });
});

// Conversations / chat (one-to-one and groups share the same store)
app.get('/api/conversations', requireAuth, (req, res) => {
  const uid = me(req).userId;
  const conversations = stores.conversations.filter(c => c.participantIds.includes(uid)).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).map(c => convView(c, uid));
  res.json({ conversations, ...unreadSummary(uid) });
});
app.get('/api/messages/unread-count', requireAuth, (req, res) => res.json(unreadSummary(me(req).userId)));
app.get('/api/conversations/:conversationId', requireAuth, (req, res) => {
  const conv = requireMember(req, res); if (!conv) return;
  res.json({ conversation: convView(conv, me(req).userId) });
});
app.post('/api/conversations', requireAuth, async (req, res) => {
  const user = me(req);
  const other = stores.users.find(u => u.userId === req.body?.otherUserId);
  if (!other) return res.status(404).json({ error: 'User not found.' });
  if (other.userId === user.userId) return res.status(400).json({ error: 'You cannot message yourself.' });
  if (isBlocked(user.userId, other.userId)) return res.status(403).json({ error: 'You cannot message this account.' });
  const conversationId = [user.userId, other.userId].sort().join('_');
  let conv = stores.conversations.find(c => c.conversationId === conversationId);
  if (!conv) {
    conv = { conversationId, isGroup: false, participantIds: [user.userId, other.userId], participantDetails: {}, lastMessage: '', lastMessageSenderId: '', createdAt: now(), updatedAt: now(), mutedBy: [], memberJoinedAt: {} };
    stores.conversations.push(conv); await persist('conversations'); notifyConversation(conv);
  }
  res.json({ conversation: convView(conv, user.userId) });
});
app.get('/api/conversations/:conversationId/messages', requireAuth, (req, res) => {
  const uid = me(req).userId; const conv = requireMember(req, res); if (!conv) return;
  const { limit, before } = pageParams(req, 40);
  const { page, nextCursor } = paginate(visibleMessages(conv, uid), limit, before);
  const messages = page.reverse().map(m => m.deleted ? { messageId: m.messageId, conversationId: m.conversationId, senderId: m.senderId, senderUsername: m.senderUsername, senderPhotoURL: m.senderPhotoURL, text: '', messageType: m.messageType, deleted: true, createdAt: m.createdAt } : m);
  res.json({ messages, nextCursor });
});
app.post('/api/conversations/:conversationId/messages', requireAuth, async (req, res) => {
  const user = me(req); const conv = requireMember(req, res); if (!conv) return;
  if (!conv.isGroup) {
    const otherId = conv.participantIds.find((p: string) => p !== user.userId);
    if (otherId && isBlocked(user.userId, otherId)) return res.status(403).json({ error: 'You cannot message this account.' });
  }
  const text = String(req.body?.text || '').trim();
  if (text.length > 4000) return res.status(400).json({ error: 'A message must be 4000 characters or fewer.' });
  let mediaURL: string | undefined;
  if (req.body?.mediaURL) {
    const media = resolveMedia(String(req.body.mediaURL), user, ['messages']);
    if (!media.ok) return res.status(400).json({ error: media.error });
    mediaURL = media.url;
  }
  const messageType = req.body?.messageType === 'reel_share' ? 'reel_share' : mediaURL ? 'image' : 'text';
  if (!text && !mediaURL && messageType !== 'reel_share') return res.status(400).json({ error: 'A message cannot be empty.' });
  let replyTo: any = null;
  if (req.body?.replyToId) {
    replyTo = stores.messages.find(m => m.messageId === req.body.replyToId && m.conversationId === conv.conversationId && !m.deleted);
    if (!replyTo) return res.status(404).json({ error: 'The message you are replying to no longer exists.' });
  }
  const clientId = typeof req.body?.clientId === 'string' ? req.body.clientId.slice(0, 64) : '';
  if (clientId) {
    const duplicate = stores.messages.find(m => m.conversationId === conv.conversationId && m.senderId === user.userId && m.clientId === clientId);
    if (duplicate) return res.status(200).json({ message: duplicate, duplicate: true });
  }
  const message: any = {
    messageId: id('msg'), conversationId: conv.conversationId, senderId: user.userId, senderUsername: user.username, senderPhotoURL: user.photoURL || '',
    text, messageType, isRead: false, readBy: [user.userId], createdAt: now(),
    ...(clientId ? { clientId } : {}), ...(mediaURL ? { mediaURL } : {}),
    ...(replyTo ? { replyToId: replyTo.messageId, replyPreview: { senderUsername: replyTo.senderUsername, text: snippet(replyTo.text, replyTo.mediaURL) } } : {}),
    ...(req.body?.reelId ? { reelId: String(req.body.reelId), reelData: req.body.reelData } : {}),
  };
  stores.messages.push(message);
  conv.lastMessage = messageType === 'reel_share' ? 'Shared a Reel' : snippet(text, mediaURL);
  conv.lastMessageSenderId = user.userId; conv.updatedAt = message.createdAt;
  await persistChat();
  notifyConversation(conv);
  res.status(201).json({ message });
  // Push notifications are sent after the response so a slow push service never delays sending.
  for (const recipientId of conv.participantIds as string[]) {
    if (recipientId === user.userId || (conv.mutedBy || []).includes(recipientId)) continue;
    const recipient = stores.users.find(u => u.userId === recipientId);
    if (!recipient || !prefsOf(recipient).messages || isBlocked(recipientId, user.userId)) continue;
    void sendPush(recipientId, {
      type: conv.isGroup ? 'group_message' : 'message', conversationId: conv.conversationId, messageId: message.messageId,
      title: conv.isGroup ? String(conv.name) : user.displayName, body: conv.isGroup ? `${user.username}: ${snippet(text, mediaURL)}` : snippet(text, mediaURL),
      senderId: user.userId, isGroup: String(Boolean(conv.isGroup)), unreadMessages: String(unreadSummary(recipientId).unreadMessages),
    });
  }
});
app.delete('/api/conversations/:conversationId/messages/:messageId', requireAuth, async (req, res) => {
  const user = me(req); const conv = requireMember(req, res); if (!conv) return;
  const message = stores.messages.find(m => m.messageId === req.params.messageId && m.conversationId === conv.conversationId);
  if (!message || message.messageType === 'system') return res.status(404).json({ error: 'Message not found.' });
  if (message.senderId !== user.userId && !(conv.isGroup && isAdmin(conv, user.userId))) return res.status(403).json({ error: 'You cannot delete this message.' });
  deleteMediaByUrl(message.mediaURL);
  Object.assign(message, { deleted: true, text: '', mediaURL: undefined, reelData: undefined, deletedAt: now() });
  await persist('messages'); notifyConversation(conv);
  res.json({ ok: true });
});
app.post('/api/conversations/:conversationId/seen', requireAuth, async (req, res) => {
  const uid = me(req).userId; const conv = requireMember(req, res); if (!conv) return;
  let changed = false;
  for (const m of visibleMessages(conv, uid)) {
    if (m.senderId === uid || m.messageType === 'system' || (m.readBy || []).includes(uid)) continue;
    m.readBy = [...(m.readBy || []), uid]; m.readAt = m.readAt || now();
    if (!conv.isGroup) m.isRead = true;
    changed = true;
  }
  if (changed) { await persist('messages'); notifyConversation(conv); }
  res.json({ ok: true, ...unreadSummary(uid) });
});
app.post('/api/conversations/:conversationId/mute', requireAuth, async (req, res) => {
  const uid = me(req).userId; const conv = requireMember(req, res); if (!conv) return;
  const muted = Boolean(req.body?.muted);
  conv.mutedBy = (conv.mutedBy || []).filter((p: string) => p !== uid);
  if (muted) conv.mutedBy.push(uid);
  await persist('conversations');
  res.json({ muted, ...unreadSummary(uid) });
});

// Group chats
const MAX_GROUP_MEMBERS = 256;
app.post('/api/groups', requireAuth, async (req, res) => {
  const user = me(req); const body = req.body || {};
  const name = String(body.name || '').trim(); const description = String(body.description || '').trim();
  if (!name || name.length > 60) return res.status(400).json({ error: 'A group name must be between 1 and 60 characters.' });
  if (description.length > 300) return res.status(400).json({ error: 'The description must be 300 characters or fewer.' });
  const memberIds: string[] = Array.isArray(body.memberIds) ? [...new Set<string>(body.memberIds.map(String))].filter(m => m !== user.userId) : [];
  if (!memberIds.length) return res.status(400).json({ error: 'Select at least one other member.' });
  if (memberIds.length + 1 > MAX_GROUP_MEMBERS) return res.status(400).json({ error: 'A group can have at most 256 members.' });
  for (const memberId of memberIds) {
    if (!stores.users.some(u => u.userId === memberId)) return res.status(404).json({ error: 'One of the selected users does not exist.' });
    if (isBlocked(user.userId, memberId)) return res.status(403).json({ error: 'You cannot add one of the selected users.' });
  }
  let photoURL = '';
  if (body.photoURL) {
    const photo = resolveMedia(String(body.photoURL), user, ['avatars']);
    if (!photo.ok || photo.mediaType !== 'image') return res.status(400).json({ error: 'The group picture must be an uploaded image.' });
    photoURL = photo.url;
  }
  const created = now();
  const memberJoinedAt: Record<string, string> = {};
  for (const p of [user.userId, ...memberIds]) memberJoinedAt[p] = created;
  const conv = {
    conversationId: id('group'), isGroup: true, name, description, photoURL, creatorId: user.userId, adminIds: [user.userId],
    participantIds: [user.userId, ...memberIds], memberJoinedAt, whoCanAdd: 'admins', mutedBy: [], participantDetails: {},
    lastMessage: '', lastMessageSenderId: '', createdAt: created, updatedAt: created,
  };
  stores.conversations.push(conv);
  addSystemMessage(conv, `@${user.username} created the group.`);
  await persistChat(); notifyConversation(conv);
  res.status(201).json({ conversation: convView(conv, user.userId), members: memberView(conv) });
});
app.get('/api/groups/:groupId', requireAuth, (req, res) => {
  const conv = requireMember(req, res); if (!conv || !conv.isGroup) { if (conv) res.status(404).json({ error: 'Group not found.' }); return; }
  res.json({ conversation: convView(conv, me(req).userId), members: memberView(conv) });
});
app.patch('/api/groups/:groupId', requireAuth, async (req, res) => {
  const user = me(req); const conv = requireMember(req, res); if (!conv) return;
  if (!conv.isGroup) return res.status(404).json({ error: 'Group not found.' });
  if (!isAdmin(conv, user.userId)) return res.status(403).json({ error: 'Only group admins can edit the group.' });
  const body = req.body || {};
  if (body.name !== undefined) {
    const name = String(body.name).trim();
    if (!name || name.length > 60) return res.status(400).json({ error: 'A group name must be between 1 and 60 characters.' });
    if (name !== conv.name) { conv.name = name; addSystemMessage(conv, `@${user.username} renamed the group to "${name}".`); }
  }
  if (body.description !== undefined) {
    if (String(body.description).length > 300) return res.status(400).json({ error: 'The description must be 300 characters or fewer.' });
    conv.description = String(body.description).trim();
  }
  if (body.photoURL !== undefined) {
    if (body.photoURL === '') conv.photoURL = '';
    else {
      const photo = resolveMedia(String(body.photoURL), user, ['avatars']);
      if (!photo.ok || photo.mediaType !== 'image') return res.status(400).json({ error: 'The group picture must be an uploaded image.' });
      conv.photoURL = photo.url; addSystemMessage(conv, `@${user.username} changed the group picture.`);
    }
  }
  if (body.whoCanAdd !== undefined) {
    if (!['admins', 'members'].includes(body.whoCanAdd)) return res.status(400).json({ error: 'Invalid invitation setting.' });
    conv.whoCanAdd = body.whoCanAdd;
  }
  await persistChat(); notifyConversation(conv);
  res.json({ conversation: convView(conv, user.userId), members: memberView(conv) });
});
app.post('/api/groups/:groupId/members', requireAuth, async (req, res) => {
  const user = me(req); const conv = requireMember(req, res); if (!conv) return;
  if (!conv.isGroup) return res.status(404).json({ error: 'Group not found.' });
  if (conv.whoCanAdd !== 'members' && !isAdmin(conv, user.userId)) return res.status(403).json({ error: 'Only group admins can add members.' });
  const userIds: string[] = Array.isArray(req.body?.userIds) ? [...new Set<string>(req.body.userIds.map(String))] : [];
  const toAdd = userIds.filter(u => !conv.participantIds.includes(u));
  if (!toAdd.length) return res.status(400).json({ error: 'Select at least one new member.' });
  if (conv.participantIds.length + toAdd.length > MAX_GROUP_MEMBERS) return res.status(400).json({ error: 'A group can have at most 256 members.' });
  for (const memberId of toAdd) {
    const target = stores.users.find(u => u.userId === memberId);
    if (!target) return res.status(404).json({ error: 'One of the selected users does not exist.' });
    if (isBlocked(user.userId, memberId)) return res.status(403).json({ error: 'You cannot add one of the selected users.' });
  }
  conv.memberJoinedAt = conv.memberJoinedAt || {};
  for (const memberId of toAdd) {
    const target = stores.users.find(u => u.userId === memberId);
    conv.participantIds.push(memberId); conv.memberJoinedAt[memberId] = now();
    addSystemMessage(conv, `@${user.username} added @${target.username}.`);
  }
  await persistChat(); notifyConversation(conv, ...toAdd);
  res.json({ members: memberView(conv) });
});
app.delete('/api/groups/:groupId/members/:userId', requireAuth, async (req, res) => {
  const user = me(req); const conv = requireMember(req, res); if (!conv) return;
  if (!conv.isGroup) return res.status(404).json({ error: 'Group not found.' });
  const targetId = req.params.userId;
  if (!conv.participantIds.includes(targetId)) return res.status(404).json({ error: 'That user is not a member of this group.' });
  if (targetId === user.userId) return res.status(400).json({ error: 'Use Leave Group to leave.' });
  if (!isAdmin(conv, user.userId)) return res.status(403).json({ error: 'Only group admins can remove members.' });
  if (targetId === conv.creatorId) return res.status(403).json({ error: 'The group creator cannot be removed.' });
  if (isAdmin(conv, targetId) && conv.creatorId !== user.userId) return res.status(403).json({ error: 'Only the group creator can remove an admin.' });
  const target = stores.users.find(u => u.userId === targetId);
  removeMember(conv, targetId);
  addSystemMessage(conv, `@${user.username} removed @${target?.username || 'a member'}.`);
  await persistChat(); notifyConversation(conv, targetId);
  res.json({ members: memberView(conv) });
});
app.post('/api/groups/:groupId/leave', requireAuth, async (req, res) => {
  const user = me(req); const conv = requireMember(req, res); if (!conv) return;
  if (!conv.isGroup) return res.status(404).json({ error: 'Group not found.' });
  removeMember(conv, user.userId);
  if (!conv.participantIds.length) deleteConversationData(conv.conversationId);
  else addSystemMessage(conv, `@${user.username} left the group.`);
  await persistChat(); notifyConversation(conv, user.userId);
  res.json({ ok: true });
});
app.post('/api/groups/:groupId/admins/:userId', requireAuth, async (req, res) => {
  const user = me(req); const conv = requireMember(req, res); if (!conv) return;
  if (!conv.isGroup) return res.status(404).json({ error: 'Group not found.' });
  if (!isAdmin(conv, user.userId)) return res.status(403).json({ error: 'Only group admins can assign admins.' });
  if (!conv.participantIds.includes(req.params.userId)) return res.status(404).json({ error: 'That user is not a member of this group.' });
  if (!isAdmin(conv, req.params.userId)) {
    conv.adminIds.push(req.params.userId);
    const target = stores.users.find(u => u.userId === req.params.userId);
    addSystemMessage(conv, `@${user.username} made @${target?.username} an admin.`);
    await persistChat(); notifyConversation(conv);
  }
  res.json({ members: memberView(conv) });
});
app.delete('/api/groups/:groupId/admins/:userId', requireAuth, async (req, res) => {
  const user = me(req); const conv = requireMember(req, res); if (!conv) return;
  if (!conv.isGroup) return res.status(404).json({ error: 'Group not found.' });
  if (conv.creatorId !== user.userId) return res.status(403).json({ error: 'Only the group creator can remove admins.' });
  if (req.params.userId === conv.creatorId) return res.status(400).json({ error: 'The group creator is always an admin.' });
  if (isAdmin(conv, req.params.userId)) {
    conv.adminIds = conv.adminIds.filter((p: string) => p !== req.params.userId);
    const target = stores.users.find(u => u.userId === req.params.userId);
    addSystemMessage(conv, `@${user.username} removed @${target?.username} as an admin.`);
    await persistChat(); notifyConversation(conv);
  }
  res.json({ members: memberView(conv) });
});

// Notifications
app.get('/api/notifications', requireAuth, (req, res) => {
  const uid = me(req).userId; const hidden = hiddenUserIds(uid);
  const { limit, before } = pageParams(req, 50);
  const mine = stores.notifications.filter(n => n.userId === uid && !hidden.has(n.senderId));
  const { page, nextCursor } = paginate(mine, limit, before);
  res.json({ notifications: page, nextCursor, unreadCount: mine.filter(n => !n.read).length });
});
app.get('/api/notifications/unread-count', requireAuth, (req, res) => {
  const uid = me(req).userId; const hidden = hiddenUserIds(uid);
  res.json({ unreadCount: stores.notifications.filter(n => n.userId === uid && !n.read && !hidden.has(n.senderId)).length });
});
app.post('/api/notifications/read-all', requireAuth, async (req, res) => {
  const uid = me(req).userId; let changed = false;
  for (const n of stores.notifications) if (n.userId === uid && !n.read) { n.read = true; changed = true; }
  if (changed) { await persist('notifications'); touchTopics(`notifications:${uid}`); }
  res.json({ ok: true });
});
app.patch('/api/notifications/:notificationId', requireAuth, async (req, res) => {
  const n = stores.notifications.find(x => x.notificationId === req.params.notificationId && x.userId === me(req).userId);
  if (!n) return res.status(404).json({ error: 'Notification not found.' });
  n.read = true; await persist('notifications'); touchTopics(`notifications:${n.userId}`);
  res.json({ ok: true });
});

// Media upload/stream. Files live under backend/data and are never static-served.
function isAllowedMediaType(folder: string, contentType: string, filename: string) {
  const type = contentType.toLowerCase().split(';')[0].trim();
  const ext = path.extname(filename).toLowerCase();
  const imageTypes = new Set(['image/jpeg','image/png','image/webp','image/gif','image/heic','image/heif']);
  const videoExtensions = new Set(['.mp4','.mov','.webm','.m4v','.avi','.mkv','.3gp','.ogv']);
  const isVideo = type.startsWith('video/') || videoExtensions.has(ext);
  if (folder === 'reels') return isVideo;
  if (folder === 'stories' || folder === 'posts') return isVideo || imageTypes.has(type) || type === 'image/*';
  return imageTypes.has(type) || type === 'image/*';
}

app.post('/api/media/upload', requireAuth, (req,res)=>{
  const user=(req as any).user;
  const folder=String(req.query.folder||'posts');
  if(!['posts','stories','reels','avatars','messages'].includes(folder)) return res.status(400).json({error:'Invalid media folder.'});
  const filename=String(req.query.filename||'upload.bin').replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,120) || 'upload.bin';
  const contentType=String(req.header('content-type')||req.query.contentType||'application/octet-stream').toLowerCase().split(';')[0].trim();
  if (!isAllowedMediaType(folder, contentType, filename)) return res.status(415).json({error:'Unsupported media type.'});

  const contentLength=Number(req.header('content-length')||0);
  if (Number.isFinite(contentLength) && contentLength > MAX_UPLOAD_BYTES) {
    req.resume();
    return res.status(413).json({error:'File exceeds the maximum allowed upload size.'});
  }

  let size=0;
  let exceeded=false;
  let responded=false;
  const mediaId=id('media');
  const finalName=`${mediaId}_${filename}`;
  const finalPath=path.join(MEDIA_DIR,finalName);
  const tempPath=`${finalPath}.part`;
  const stream=fs.createWriteStream(tempPath,{flags:'wx'});
  const cleanup=()=>fs.promises.rm(tempPath,{force:true}).catch(()=>{});

  req.on('data',(chunk:Buffer)=>{
    if (exceeded) return;
    size += chunk.length;
    if (size > MAX_UPLOAD_BYTES) {
      exceeded=true;
      stream.destroy();
      void cleanup();
      if (!res.headersSent) { responded=true; res.status(413).json({error:'File exceeds the maximum allowed upload size.'}); }
      req.resume();
    }
  });
  req.on('error',()=>{
    if (responded) return;
    stream.destroy();
    void cleanup();
    if(!res.headersSent) { responded=true; res.status(400).json({error:'Upload failed.'}); }
  });
  stream.on('error',()=>{
    if (responded || exceeded) return;
    void cleanup();
    if(!res.headersSent) { responded=true; res.status(500).json({error:'Upload failed.'}); }
  });
  stream.on('finish',async()=>{
    if (exceeded || responded) return;
    if(size<=0) { await cleanup(); return res.status(400).json({error:'Upload cannot be empty.'}); }
    try {
      await fs.promises.rename(tempPath,finalPath);
      stores.media.push({mediaId,ownerId:user.userId,folder,filename,storedName:finalName,contentType,size,createdAt:now()});
      await persist('media');
      res.status(201).json({mediaId,url:`/api/media/${mediaId}`,mediaStreamUrl:`/api/media/${mediaId}`,size,contentType});
    } catch {
      await cleanup();
      if(!res.headersSent) res.status(500).json({error:'Upload failed.'});
    }
  });
  req.pipe(stream);
});
app.get('/api/media/:mediaId', async(req,res)=>{
  const media=stores.media.find(m=>m.mediaId===req.params.mediaId); if(!media)return res.status(404).send('Media not found.'); const filePath=path.join(MEDIA_DIR,media.storedName); if(!fs.existsSync(filePath))return res.status(404).send('Media not found.');
  const stat=await fs.promises.stat(filePath); const range=req.headers.range; res.setHeader('Accept-Ranges','bytes');res.setHeader('Content-Type',media.contentType||'application/octet-stream');res.setHeader('Cache-Control','public, max-age=31536000, immutable');
  if(range){const match=/bytes=(\d*)-(\d*)/.exec(range);if(!match)return res.status(416).end();let start=match[1]?Number(match[1]):0;let end=match[2]?Number(match[2]):stat.size-1;if(start>=stat.size||start>end){res.setHeader('Content-Range',`bytes */${stat.size}`);return res.status(416).end();}end=Math.min(end,stat.size-1);res.status(206);res.setHeader('Content-Range',`bytes ${start}-${end}/${stat.size}`);res.setHeader('Content-Length',end-start+1);return fs.createReadStream(filePath,{start,end}).pipe(res);}res.setHeader('Content-Length',stat.size);fs.createReadStream(filePath).pipe(res);
});
app.delete('/api/media/:mediaId', requireAuth, async(req,res)=>{const user=(req as any).user;const idx=stores.media.findIndex(m=>m.mediaId===req.params.mediaId);if(idx<0)return res.status(404).json({error:'Media not found.'});if(stores.media[idx].ownerId!==user.userId)return res.status(403).json({error:'Forbidden.'});const item=stores.media[idx];stores.media.splice(idx,1);await fs.promises.rm(path.join(MEDIA_DIR,item.storedName),{force:true});await persist('media');res.json({ok:true});});

// Server-sent events for app-level realtime updates.
app.get('/api/events', requireAuth,(req,res)=>{res.setHeader('Content-Type','text/event-stream');res.setHeader('Cache-Control','no-cache, no-transform');res.setHeader('Connection','keep-alive');res.flushHeaders?.();res.write(`event: ready\ndata: {}\n\n`);sseClients.set(res,(req as any).user.userId);const heartbeat=setInterval(()=>{try{res.write(': heartbeat\n\n')}catch{clearInterval(heartbeat);sseClients.delete(res)}},15000);req.on('close',()=>{clearInterval(heartbeat);sseClients.delete(res);});});

// Clean expired stories and expired sessions on startup.
stores.stories=stores.stories.filter(s=>!s.expiresAt||new Date(s.expiresAt).getTime()>Date.now());
stores.sessions=stores.sessions.filter(s=>new Date(s.expiresAt).getTime()>Date.now());
void persist('stories'); void persist('sessions');

async function start() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: 'spa' });
    app.use(vite.middlewares);
  } else {
    const distPath=path.join(ROOT,'dist'); app.use(express.static(distPath)); app.get('*',(_req,res)=>res.sendFile(path.join(distPath,'index.html')));
  }
  app.listen(PORT,'0.0.0.0',()=>console.log(`Tsukyo backend listening on http://0.0.0.0:${PORT}`));
}
start().catch(err=>{console.error('Failed to start Tsukyo server:',err);process.exit(1)});
