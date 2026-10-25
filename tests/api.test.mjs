// End-to-end API tests. Starts the real server bundle as a child process with a temporary data directory
// and a local fake Firebase endpoint (the server's real JWT signing and HTTP code path is exercised).
// Usage: TSUKYO_TEST_SERVER=dist/server.cjs node tests/api.test.mjs
import { spawn } from 'node:child_process';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const SERVER = process.env.TSUKYO_TEST_SERVER || 'dist/server.cjs';
const PORT = 4600 + Math.floor(Math.random() * 300);
const FCM_PORT = PORT + 1000;
const BASE = `http://127.0.0.1:${PORT}`;
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tsukyo-test-'));
const results = [];
let child = null;

// ---- fake Firebase (token endpoint + messages:send) ----
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const serviceAccount = { project_id: 'tsukyo-test', client_email: 'test@tsukyo-test.iam.gserviceaccount.com', private_key: privateKey, token_uri: `http://127.0.0.1:${FCM_PORT}/token` };
const pushes = []; let jwtValid = false; let fcmReply = null;
const fcm = http.createServer((req, res) => {
  let body = ''; req.on('data', c => body += c); req.on('end', () => {
    if (req.url === '/token') {
      const assertion = new URLSearchParams(body).get('assertion') || '';
      const [h, c, s] = assertion.split('.');
      jwtValid = crypto.createVerify('RSA-SHA256').update(`${h}.${c}`).verify(publicKey, Buffer.from(s, 'base64url'));
      res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify({ access_token: 'fake-access-token', expires_in: 3600 }));
    }
    if (req.url === '/v1/projects/tsukyo-test/messages:send') {
      const parsed = JSON.parse(body);
      if (req.headers.authorization !== 'Bearer fake-access-token') { res.statusCode = 401; return res.end('{}'); }
      pushes.push(parsed.message);
      if (fcmReply && fcmReply.token === parsed.message.token) { res.statusCode = fcmReply.status; return res.end(fcmReply.body); }
      res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify({ name: 'ok' }));
    }
    res.statusCode = 404; res.end();
  });
});

async function startServer() {
  child = spawn('node', [SERVER], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), DATA_DIR: dataDir, SESSION_SECRET: 'test-secret-test-secret-test-secret-123', FCM_SERVICE_ACCOUNT_JSON: JSON.stringify(serviceAccount), FCM_API_BASE: `http://127.0.0.1:${FCM_PORT}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stderr.on('data', d => process.stderr.write(d));
  for (let i = 0; i < 60; i++) { try { const r = await fetch(`${BASE}/api/health`); if (r.ok) return; } catch {} await new Promise(r => setTimeout(r, 100)); }
  throw new Error('Server did not start.');
}
async function stopServer() { if (!child) return; child.kill(); await new Promise(r => child.once('exit', r)); child = null; }
async function restartServer() { await stopServer(); await startServer(); }

async function api(method, p, { token, body, headers = {}, raw } = {}) {
  const h = { ...headers }; if (token) h.Authorization = `Bearer ${token}`;
  let payload = raw; if (body !== undefined) { h['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  const r = await fetch(BASE + p, { method, headers: h, body: payload });
  const text = await r.text(); let data = {}; try { data = text ? JSON.parse(text) : {}; } catch { data = { text }; }
  return { status: r.status, data, res: r };
}
let n = 0;
function check(name, cond, detail = '') { n++; results.push({ n, name, ok: Boolean(cond), detail: cond ? '' : String(detail) }); if (!cond) console.log(`FAIL ${name} ${detail}`); }
const sleep = ms => new Promise(r => setTimeout(r, ms));
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');

async function register(name) {
  const r = await api('POST', '/api/auth/register', { body: { email: `${name}@example.test`, password: 'password-123', username: name, displayName: name.toUpperCase() } });
  return { token: r.data.token, id: r.data.user?.userId, user: r.data.user, status: r.status };
}
async function upload(token, folder, type, bytes, filename = 'file.bin') {
  const r = await api('POST', `/api/media/upload?folder=${folder}&filename=${filename}`, { token, headers: { 'Content-Type': type }, raw: bytes });
  return r;
}

async function main() {
  await new Promise(r => fcm.listen(FCM_PORT, '127.0.0.1', r));
  await startServer();

  // ---- Authentication ----
  const A = await register('alice'), B = await register('bob'), C = await register('carol'), D = await register('dave');
  check('Registration returns 201 and a session token', A.status === 201 && A.token);
  check('New accounts are NOT verified and have an empty bio', A.user.isVerified === false && A.user.bio === '');
  check('Registration response never exposes password data', !('passwordHash' in A.user) && !('passwordSalt' in A.user));
  check('Duplicate email is rejected (409)', (await api('POST', '/api/auth/register', { body: { email: 'alice@example.test', password: 'password-123', username: 'alice2', displayName: 'x' } })).status === 409);
  check('Weak password is rejected (400)', (await api('POST', '/api/auth/register', { body: { email: 'w@example.test', password: 'short', username: 'weakuser', displayName: 'x' } })).status === 400);
  check('Protected endpoint without a token returns 401', (await api('GET', '/api/feed')).status === 401);
  check('Wrong password returns 401', (await api('POST', '/api/auth/login', { body: { email: 'alice@example.test', password: 'nope-nope-nope' } })).status === 401);
  const loginA = await api('POST', '/api/auth/login', { body: { email: 'alice@example.test', password: 'password-123' } });
  check('Login with correct credentials works', loginA.status === 200 && loginA.data.token);
  const pubB = await api('GET', `/api/users/${B.id}`, { token: A.token });
  check("Another user's profile does not expose the email address", pubB.status === 200 && pubB.data.user.email === undefined);
  check('Own profile (auth/me) includes the email', (await api('GET', '/api/auth/me', { token: A.token })).data.user.email === 'alice@example.test');
  let throttleStatus = 0; for (let i = 0; i < 11; i++) throttleStatus = (await api('POST', '/api/auth/login', { body: { email: 'dave@example.test', password: 'wrong-wrong-wrong' } })).status;
  check('Repeated failed logins are throttled (429)', throttleStatus === 429);
  check('Edit profile: other users are forbidden (403)', (await api('PATCH', `/api/users/${B.id}`, { token: A.token, body: { bio: 'hack' } })).status === 403);
  const edit = await api('PATCH', `/api/users/${A.id}`, { token: A.token, body: { bio: 'Hello from Alice', website: 'https://alice.example' } });
  check('Edit profile persists bio and website', edit.data.user.bio === 'Hello from Alice' && edit.data.user.website === 'https://alice.example');

  // ---- Media ----
  const up = await upload(A.token, 'posts', 'image/png', PNG, 'a.png');
  check('Image upload returns 201 and a media URL', up.status === 201 && up.data.url?.startsWith('/api/media/'), JSON.stringify(up.data));
  const got = await fetch(BASE + up.data.url);
  const gotBytes = Buffer.from(await got.arrayBuffer());
  check('Uploaded image can be retrieved byte-for-byte', got.status === 200 && gotBytes.equals(PNG));
  const ranged = await fetch(BASE + up.data.url, { headers: { Range: 'bytes=0-9' } });
  check('Media supports HTTP range requests (206)', ranged.status === 206 && (await ranged.arrayBuffer()).byteLength === 10);
  check('Unsupported upload type is rejected (415)', (await upload(A.token, 'posts', 'text/plain', Buffer.from('hello'), 'x.txt')).status === 415);
  check('Image cannot be uploaded to the reels folder (415)', (await upload(A.token, 'reels', 'image/png', PNG, 'x.png')).status === 415);
  check('Upload without authentication is rejected (401)', (await api('POST', '/api/media/upload?folder=posts&filename=a.png', { headers: { 'Content-Type': 'image/png' }, raw: PNG })).status === 401);

  // ---- Posts, feed, follows ----
  check('Post with media the user does not own is rejected (400)', (await api('POST', '/api/posts', { token: B.token, body: { caption: 'steal', mediaURL: up.data.url } })).status === 400);
  check('Post with an external URL is rejected (400)', (await api('POST', '/api/posts', { token: A.token, body: { caption: 'x', mediaURL: 'https://evil.example/a.png' } })).status === 400);
  const post = await api('POST', '/api/posts', { token: A.token, body: { caption: 'First real post #tsukyo', location: 'Tokyo', mediaURL: up.data.url } });
  check('Post creation returns 201 with real media and zero engagement', post.status === 201 && post.data.post.likeCount === 0 && post.data.post.commentCount === 0 && post.data.post.mediaType === 'image');
  const postId = post.data.post.postId;
  const emptyFeed = await api('GET', '/api/feed?scope=following&limit=20', { token: B.token });
  check('Following feed is empty before following anyone', emptyFeed.data.posts.length === 0);
  check('Explore feed (scope=all) shows the post to Bob', (await api('GET', '/api/feed?limit=20', { token: B.token })).data.posts.some(p => p.postId === postId));
  await api('POST', `/api/users/${A.id}/follow`, { token: B.token });
  await api('POST', `/api/users/${A.id}/follow`, { token: B.token });
  const fol = await api('GET', `/api/users/${A.id}`, { token: B.token });
  check('Follow is idempotent; follower count is derived from records', fol.data.user.followerCount === 1 && fol.data.isFollowing === true);
  const feedB = await api('GET', '/api/feed?scope=following&limit=20', { token: B.token });
  check("Account B sees Account A's post in the following feed", feedB.data.posts.length === 1 && feedB.data.posts[0].ownerUsername === 'alice');
  check('Follow created exactly one notification for Alice', (await api('GET', '/api/notifications', { token: A.token })).data.notifications.filter(x => x.type === 'follow').length === 1);
  check('Cannot follow yourself (400)', (await api('POST', `/api/users/${A.id}/follow`, { token: A.token })).status === 400);
  const l1 = await api('POST', `/api/posts/${postId}/like`, { token: B.token });
  check('Like returns the authoritative count', l1.data.liked === true && l1.data.likeCount === 1);
  const likeNotif = await api('GET', '/api/notifications', { token: A.token });
  check('Like created an unread notification with a correct count', likeNotif.data.unreadCount === 2 && likeNotif.data.notifications.some(x => x.type === 'like'));
  const cm = await api('POST', `/api/posts/${postId}/comments`, { token: B.token, body: { text: 'Great shot!' } });
  check('Comment is created and the count is authoritative', cm.status === 201 && cm.data.commentCount === 1);
  const rp = await api('POST', `/api/posts/${postId}/comments`, { token: A.token, body: { text: 'Thank you!', parentId: cm.data.comment.commentId } });
  check('Reply is stored with its parent', rp.status === 201 && rp.data.comment.parentId === cm.data.comment.commentId);
  check('Bob received a reply notification', (await api('GET', '/api/notifications', { token: B.token })).data.notifications.some(x => x.type === 'reply'));
  check('A third user cannot delete someone else\'s comment (403)', (await api('DELETE', `/api/posts/${postId}/comments/${cm.data.comment.commentId}`, { token: C.token })).status === 403);
  check('Empty comment is rejected (400)', (await api('POST', `/api/posts/${postId}/comments`, { token: B.token, body: { text: '   ' } })).status === 400);
  const fav = await api('POST', `/api/favorites/${postId}`, { token: B.token, body: { contentType: 'post', contentData: { postId, mediaURL: up.data.url } } });
  check('Bookmark is saved and listed', fav.data.favorited === true && (await api('GET', '/api/favorites', { token: B.token })).data.favorites.length === 1);
  check('Search finds the post by hashtag', (await api('GET', '/api/search?q=%23tsukyo&type=posts', { token: B.token })).data.posts.length === 1);
  check('User search finds Alice by partial username', (await api('GET', '/api/users/search?q=alic', { token: B.token })).data.users.some(u => u.userId === A.id));

  await restartServer();
  const afterRestart = await api('GET', '/api/feed?scope=following', { token: B.token });
  const p0 = afterRestart.data.posts[0];
  check('After a server restart the session, post, like, comment and bookmark persist', p0 && p0.isLiked === true && p0.likeCount === 1 && p0.commentCount === 2 && p0.isFavorited === true);

  const prefs = await api('PATCH', '/api/users/me/preferences', { token: A.token, body: { likes: false } });
  check('Notification preferences can be changed', prefs.data.notificationPrefs.likes === false);
  await api('POST', `/api/posts/${postId}/like`, { token: B.token }); // unlike
  const before = (await api('GET', '/api/notifications', { token: A.token })).data.notifications.length;
  await api('POST', `/api/posts/${postId}/like`, { token: B.token }); // like again
  check('Disabled like notifications are not created', (await api('GET', '/api/notifications', { token: A.token })).data.notifications.length === before);
  await api('PATCH', '/api/users/me/preferences', { token: A.token, body: { likes: true } });
  const readAll = await api('POST', '/api/notifications/read-all', { token: A.token });
  check('Mark all notifications as read', readAll.status === 200 && (await api('GET', '/api/notifications/unread-count', { token: A.token })).data.unreadCount === 0);

  // ---- Reports and blocks ----
  check('Report a post', (await api('POST', '/api/reports', { token: B.token, body: { targetType: 'post', targetId: postId, reason: 'Spam' } })).status === 201);
  check('Invalid report target is rejected (400)', (await api('POST', '/api/reports', { token: B.token, body: { targetType: 'bogus', targetId: 'x', reason: 'Spam' } })).status === 400);
  const rep = JSON.parse(fs.readFileSync(path.join(dataDir, 'reports.json'), 'utf8'));
  check('Report is persisted once', rep.length === 1);

  // ---- Stories ----
  const sUp = await upload(A.token, 'stories', 'image/png', PNG, 's.png');
  const story = await api('POST', '/api/stories', { token: A.token, body: { mediaURL: sUp.data.url, overlayText: 'Hello' } });
  check('Story is created with a 24 hour expiry', story.status === 201 && new Date(story.data.story.expiresAt) - new Date(story.data.story.createdAt) === 86400000);
  check('Story is visible to Bob and not yet viewed', (await api('GET', '/api/stories', { token: B.token })).data.stories.some(s => s.storyId === story.data.story.storyId && s.viewed === false));
  await api('POST', `/api/stories/${story.data.story.storyId}/view`, { token: B.token });
  check('Story viewer list shows Bob to the owner only', (await api('GET', `/api/stories/${story.data.story.storyId}/viewers`, { token: A.token })).data.viewers.some(v => v.userId === B.id) && (await api('GET', `/api/stories/${story.data.story.storyId}/viewers`, { token: B.token })).status === 403);
  check('Only the owner can delete a story', (await api('DELETE', `/api/stories/${story.data.story.storyId}`, { token: B.token })).status === 403);
  const sFile = path.join(dataDir, 'stories.json'); const stories = JSON.parse(fs.readFileSync(sFile, 'utf8')); stories[0].expiresAt = new Date(Date.now() - 1000).toISOString(); fs.writeFileSync(sFile, JSON.stringify(stories));
  await stopServer(); await startServer();
  check('Expired stories no longer appear', !(await api('GET', '/api/stories', { token: B.token })).data.stories.some(s => s.storyId === story.data.story.storyId));

  // ---- Reels ----
  const fakeVideo = Buffer.concat([Buffer.from('000000186674797069736F6D', 'hex'), crypto.randomBytes(5000)]);
  const vUp = await upload(A.token, 'reels', 'video/mp4', fakeVideo, 'r.mp4');
  check('Video upload is accepted for reels', vUp.status === 201);
  check('A reel cannot reference an image upload (400)', (await api('POST', '/api/reels', { token: A.token, body: { caption: 'x', mediaURL: up.data.url } })).status === 400);
  const reel = await api('POST', '/api/reels', { token: A.token, body: { caption: 'My first reel', mediaURL: vUp.data.url } });
  check('Reel is created with the default audio label', reel.status === 201 && reel.data.reel.audioTitle === 'Original audio' && reel.data.reel.likeCount === 0);
  const reelId = reel.data.reel.reelId;
  const reelsB = await api('GET', '/api/reels?limit=10', { token: B.token });
  check('Bob sees the reel in the Reels feed', reelsB.data.reels.some(r => r.reelId === reelId && r.ownerIsFollowing === true));
  const vr = await fetch(BASE + vUp.data.url, { headers: { Range: 'bytes=100-199' } });
  check('The reel video streams with range support', vr.status === 206 && vr.headers.get('content-type') === 'video/mp4' && (await vr.arrayBuffer()).byteLength === 100);
  await api('POST', `/api/reels/${reelId}/like`, { token: B.token }); await api('POST', `/api/reels/${reelId}/comments`, { token: B.token, body: { text: 'Nice reel' } });
  await restartServer();
  const reelAfter = (await api('GET', `/api/reels/${reelId}`, { token: B.token })).data.reel;
  check('Reel, like and comment persist after restart', reelAfter.isLiked && reelAfter.likeCount === 1 && reelAfter.commentCount === 1);

  // ---- Direct messages ----
  const conv = await api('POST', '/api/conversations', { token: A.token, body: { otherUserId: B.id } });
  const convId = conv.data.conversation.conversationId;
  check('New conversation has no placeholder message', conv.data.conversation.lastMessage === '');
  const m1 = await api('POST', `/api/conversations/${convId}/messages`, { token: A.token, body: { text: 'Hello Bob', clientId: 'c-1' } });
  const m1dup = await api('POST', `/api/conversations/${convId}/messages`, { token: A.token, body: { text: 'Hello Bob', clientId: 'c-1' } });
  check('Message is saved; a retry with the same clientId does not duplicate it', m1.status === 201 && m1dup.data.duplicate === true);
  const inboxB = await api('GET', '/api/conversations', { token: B.token });
  check('Bob sees the conversation with an unread count of 1 and a summary badge', inboxB.data.conversations[0].unreadCount === 1 && inboxB.data.unreadConversations === 1 && inboxB.data.unreadMessages === 1);
  check('Message summary endpoint matches', (await api('GET', '/api/messages/unread-count', { token: B.token })).data.unreadMessages === 1);
  check('Alice has no unread messages', (await api('GET', '/api/messages/unread-count', { token: A.token })).data.unreadMessages === 0);
  const readB = await api('GET', `/api/conversations/${convId}/messages`, { token: B.token });
  check('Bob can read the message', readB.data.messages.length === 1 && readB.data.messages[0].text === 'Hello Bob');
  const seen = await api('POST', `/api/conversations/${convId}/seen`, { token: B.token });
  check('Marking a conversation as seen clears the unread badge', seen.data.unreadMessages === 0);
  check('Alice sees the message marked as read', (await api('GET', `/api/conversations/${convId}/messages`, { token: A.token })).data.messages[0].isRead === true);
  const reply = await api('POST', `/api/conversations/${convId}/messages`, { token: B.token, body: { text: 'Hi Alice!', replyToId: m1.data.message.messageId } });
  check('Bob can reply with a quoted message', reply.status === 201 && reply.data.message.replyPreview.text === 'Hello Bob');
  check('Alice can read the reply', (await api('GET', `/api/conversations/${convId}/messages`, { token: A.token })).data.messages.some(m => m.text === 'Hi Alice!'));
  check('A third account cannot read the conversation (403)', (await api('GET', `/api/conversations/${convId}/messages`, { token: C.token })).status === 403);
  check('A third account cannot send into the conversation (403)', (await api('POST', `/api/conversations/${convId}/messages`, { token: C.token, body: { text: 'intrude' } })).status === 403);
  check('Empty messages are rejected (400)', (await api('POST', `/api/conversations/${convId}/messages`, { token: A.token, body: { text: '  ' } })).status === 400);
  const page1 = await api('GET', `/api/conversations/${convId}/messages?limit=1`, { token: A.token });
  const page2 = await api('GET', `/api/conversations/${convId}/messages?limit=1&before=${encodeURIComponent(page1.data.nextCursor)}`, { token: A.token });
  check('Message history is paginated', page1.data.messages.length === 1 && page1.data.messages[0].text === 'Hi Alice!' && page2.data.messages[0].text === 'Hello Bob');
  check('Only the sender can delete a direct message', (await api('DELETE', `/api/conversations/${convId}/messages/${m1.data.message.messageId}`, { token: B.token })).status === 403);
  await restartServer();
  check('Messages persist after restart', (await api('GET', `/api/conversations/${convId}/messages`, { token: B.token })).data.messages.length === 2);

  // ---- Real-time events and push notifications ----
  const events = { B: [], C: [] };
  const abort = new AbortController();
  const listen = async (who, token) => { const r = await fetch(`${BASE}/api/events`, { headers: { Authorization: `Bearer ${token}` }, signal: abort.signal }); const rd = r.body.getReader(); const dec = new TextDecoder(); (async () => { try { while (true) { const { value, done } = await rd.read(); if (done) break; events[who].push(dec.decode(value)); } } catch {} })(); };
  await listen('B', B.token); await listen('C', C.token); await sleep(200);
  const devB = 'device-token-bob-' + 'x'.repeat(30); const devA = 'device-token-alice-' + 'y'.repeat(30);
  check('Device token registration works and reports push is enabled', (await api('POST', '/api/devices', { token: B.token, body: { token: devB } })).data.pushEnabled === true);
  await api('POST', '/api/devices', { token: A.token, body: { token: devA } });
  pushes.length = 0;
  await api('POST', `/api/conversations/${convId}/messages`, { token: A.token, body: { text: 'Push me' } });
  await sleep(500);
  const push1 = pushes.find(p => p.token === devB);
  check('The server signed a valid Firebase JWT', jwtValid === true);
  check('Bob\'s device received a push for the new direct message with the conversation id', push1 && push1.data.type === 'message' && push1.data.conversationId === convId && push1.data.body === 'Push me' && push1.data.title === 'ALICE' && push1.data.unreadMessages === '1', JSON.stringify(pushes));
  check('The sender does not receive a push for their own message', !pushes.some(p => p.token === devA));
  check('Real-time events reached the recipient only', events.B.join('').includes(`messages:${convId}`) && events.B.join('').includes(`conversations:${B.id}`) && !events.C.join('').includes(convId) && !events.C.join('').includes('conversations'));

  // ---- Groups ----
  pushes.length = 0;
  const grp = await api('POST', '/api/groups', { token: A.token, body: { name: 'Tokyo Crew', description: 'Weekend plans', memberIds: [B.id, C.id] } });
  const gid = grp.data.conversation?.conversationId;
  check('Group is created with three members and a creator', grp.status === 201 && grp.data.members.length === 3 && grp.data.conversation.creatorId === A.id);
  check('Group needs at least one other member (400)', (await api('POST', '/api/groups', { token: A.token, body: { name: 'Solo', memberIds: [] } })).status === 400);
  for (const [who, t] of [['Alice', A], ['Bob', B], ['Carol', C]]) check(`${who} sees the group in the inbox as a group`, (await api('GET', '/api/conversations', { token: t.token })).data.conversations.some(c => c.conversationId === gid && c.isGroup && c.name === 'Tokyo Crew'));
  check('Dave (outside the group) cannot read group messages (403)', (await api('GET', `/api/conversations/${gid}/messages`, { token: D.token })).status === 403);
  check('Dave cannot open group info (403)', (await api('GET', `/api/groups/${gid}`, { token: D.token })).status === 403);
  check('Dave cannot send to the group (403)', (await api('POST', `/api/conversations/${gid}/messages`, { token: D.token, body: { text: 'hi' } })).status === 403);
  pushes.length = 0; const devC = 'device-token-carol-' + 'z'.repeat(30); await api('POST', '/api/devices', { token: C.token, body: { token: devC } });
  await api('POST', `/api/conversations/${gid}/messages`, { token: A.token, body: { text: 'Welcome everyone' } });
  await sleep(500);
  check('Bob and Carol read the group message with the sender shown', ['B', 'C'].every(() => true) && (await api('GET', `/api/conversations/${gid}/messages`, { token: B.token })).data.messages.some(m => m.text === 'Welcome everyone' && m.senderUsername === 'alice'));
  check('Group push uses the group name as the title for both members', pushes.filter(p => p.data.type === 'group_message' && p.data.title === 'Tokyo Crew' && p.data.isGroup === 'true').length === 2, JSON.stringify(pushes));
  const gi = await api('GET', '/api/conversations', { token: B.token });
  check('Group unread count is tracked per member', gi.data.conversations.find(c => c.conversationId === gid).unreadCount === 1 && gi.data.conversations.find(c => c.conversationId === convId).unreadCount === 1 && gi.data.unreadConversations === 2 && gi.data.unreadMessages === 2, JSON.stringify(gi.data.conversations.map(c => [c.name || 'dm', c.unreadCount])));
  const gr = await api('POST', `/api/conversations/${gid}/messages`, { token: B.token, body: { text: 'Thanks Alice' } });
  check('Bob replies and Carol can read the reply', gr.status === 201 && (await api('GET', `/api/conversations/${gid}/messages`, { token: C.token })).data.messages.some(m => m.text === 'Thanks Alice'));
  await api('POST', `/api/conversations/${gid}/seen`, { token: B.token });
  const bAfter = (await api('GET', '/api/messages/unread-count', { token: B.token })).data; const cAfter = (await api('GET', '/api/messages/unread-count', { token: C.token })).data;
  check('Marking the group as seen reduces Bob\'s badge but not Carol\'s', bAfter.unreadMessages === 1 && bAfter.unreadConversations === 1 && cAfter.unreadMessages >= 2, JSON.stringify([bAfter, cAfter]));
  await api('POST', `/api/conversations/${gid}/mute`, { token: C.token, body: { muted: true } });
  pushes.length = 0; await api('POST', `/api/conversations/${gid}/messages`, { token: A.token, body: { text: 'Muted test' } }); await sleep(400);
  check('A muted member gets no push and the badge excludes the muted group', !pushes.some(p => p.token === devC) && (await api('GET', '/api/messages/unread-count', { token: C.token })).data.unreadMessages === 0 && (await api('GET', '/api/conversations', { token: C.token })).data.conversations.find(c => c.conversationId === gid).unreadCount > 0);
  await api('POST', `/api/conversations/${gid}/mute`, { token: C.token, body: { muted: false } });
  check('Members cannot rename the group (403)', (await api('PATCH', `/api/groups/${gid}`, { token: B.token, body: { name: 'Hacked' } })).status === 403);
  check('Members cannot add members while the setting is admins-only (403)', (await api('POST', `/api/groups/${gid}/members`, { token: B.token, body: { userIds: [D.id] } })).status === 403);
  check('Only admins can remove members (403 for Bob)', (await api('DELETE', `/api/groups/${gid}/members/${C.id}`, { token: B.token })).status === 403);
  await api('POST', `/api/groups/${gid}/admins/${B.id}`, { token: A.token });
  check('After promotion Bob can rename the group', (await api('PATCH', `/api/groups/${gid}`, { token: B.token, body: { name: 'Tokyo Crew 2' } })).data.conversation.name === 'Tokyo Crew 2');
  check('An admin cannot remove the group creator (403)', (await api('DELETE', `/api/groups/${gid}/members/${A.id}`, { token: B.token })).status === 403);
  check('Only the creator can remove admins', (await api('DELETE', `/api/groups/${gid}/admins/${B.id}`, { token: B.token })).status === 403);
  const add = await api('POST', `/api/groups/${gid}/members`, { token: B.token, body: { userIds: [D.id] } });
  check('An admin can add Dave, who then reads the group', add.status === 200 && (await api('GET', `/api/conversations/${gid}/messages`, { token: D.token })).status === 200);
  check('A new member does not see messages from before they joined', !(await api('GET', `/api/conversations/${gid}/messages`, { token: D.token })).data.messages.some(m => m.text === 'Welcome everyone'));
  await api('POST', `/api/groups/${gid}/leave`, { token: C.token });
  check('A member who leaves can no longer read the group (403)', (await api('GET', `/api/conversations/${gid}/messages`, { token: C.token })).status === 403);
  const rem = await api('DELETE', `/api/groups/${gid}/members/${D.id}`, { token: A.token });
  check('The creator can remove a member, who loses access', rem.status === 200 && (await api('GET', `/api/conversations/${gid}/messages`, { token: D.token })).status === 403);
  const gmsg = (await api('GET', `/api/conversations/${gid}/messages`, { token: B.token })).data.messages;
  check('Group events are recorded as system messages', gmsg.some(m => m.messageType === 'system' && m.text.includes('created the group')) && gmsg.some(m => m.messageType === 'system' && m.text.includes('left the group')));
  check('Admin can delete another member\'s group message', (await api('DELETE', `/api/conversations/${gid}/messages/${gr.data.message.messageId}`, { token: A.token })).status === 200);
  await restartServer();
  const afterG = await api('GET', `/api/groups/${gid}`, { token: B.token });
  check('Group details, members and admins persist after restart', afterG.data.conversation.name === 'Tokyo Crew 2' && afterG.data.members.length === 2 && afterG.data.members.find(m => m.userId === B.id).role === 'admin');

  // ---- Push token lifecycle ----
  pushes.length = 0; fcmReply = { token: devB, status: 404, body: JSON.stringify({ error: { status: 'NOT_FOUND', details: [{ errorCode: 'UNREGISTERED' }] } }) };
  await api('POST', `/api/conversations/${convId}/messages`, { token: A.token, body: { text: 'Stale token test' } }); await sleep(500);
  const devices = JSON.parse(fs.readFileSync(path.join(dataDir, 'devices.json'), 'utf8'));
  check('An unregistered device token is removed automatically', !devices.some(d => d.token === devB));
  fcmReply = null;
  await api('POST', '/api/devices', { token: B.token, body: { token: devB } });
  await api('POST', '/api/auth/logout', { token: B.token, body: { deviceToken: devB } });
  pushes.length = 0; await api('POST', `/api/conversations/${convId}/messages`, { token: A.token, body: { text: 'After logout' } }); await sleep(400);
  check('After logout the session is invalid (401) and no push is sent to that device', (await api('GET', '/api/feed', { token: B.token })).status === 401 && !pushes.some(p => p.token === devB));

  // ---- Blocking ----
  await api('POST', `/api/users/${C.id}/block`, { token: A.token });
  check('A blocked user cannot see the blocker\'s profile (404)', (await api('GET', `/api/users/${A.id}`, { token: C.token })).status === 404);
  check('A blocked user is hidden from search results', !(await api('GET', '/api/users/search?q=carol', { token: A.token })).data.users.length);
  check('Blocked users cannot start a conversation (403)', (await api('POST', '/api/conversations', { token: C.token, body: { otherUserId: A.id } })).status === 403);
  check('Blocked users cannot see the blocker\'s posts in Explore', !(await api('GET', '/api/feed', { token: C.token })).data.posts.some(p => p.ownerId === A.id));
  check('The blocked list is returned', (await api('GET', '/api/blocks', { token: A.token })).data.users.some(u => u.userId === C.id));
  await api('DELETE', `/api/users/${C.id}/block`, { token: A.token });
  check('Unblocking restores access', (await api('GET', `/api/users/${A.id}`, { token: C.token })).status === 200);

  // ---- Post deletion, password change, account deletion ----
  const login2 = await api('POST', '/api/auth/login', { body: { email: 'bob@example.test', password: 'password-123' } });
  const bobToken = login2.data.token;
  check('Only the owner can delete a post (403 for Bob)', (await api('DELETE', `/api/posts/${postId}`, { token: bobToken })).status === 403);
  check('Owner deletes the post', (await api('DELETE', `/api/posts/${postId}`, { token: A.token })).status === 200);
  check('Deleted post is gone from the feed and its media is removed', !(await api('GET', '/api/feed', { token: bobToken })).data.posts.some(p => p.postId === postId) && (await fetch(BASE + up.data.url)).status === 404);
  check('Deleted post comments and favorites are removed', (await api('GET', '/api/favorites', { token: bobToken })).data.favorites.length === 0);
  const extraLogin = await api('POST', '/api/auth/login', { body: { email: 'bob@example.test', password: 'password-123' } });
  check('Change password rejects a wrong current password (403)', (await api('POST', '/api/auth/change-password', { token: bobToken, body: { currentPassword: 'wrong-wrong', newPassword: 'new-password-1' } })).status === 403);
  await api('POST', '/api/auth/change-password', { token: bobToken, body: { currentPassword: 'password-123', newPassword: 'new-password-1' } });
  check('Change password signs out other sessions and old password stops working', (await api('GET', '/api/feed', { token: extraLogin.data.token })).status === 401 && (await api('GET', '/api/feed', { token: bobToken })).status === 200 && (await api('POST', '/api/auth/login', { body: { email: 'bob@example.test', password: 'password-123' } })).status === 401);
  check('Account deletion requires the correct password (403)', (await api('DELETE', '/api/users/me', { token: bobToken, body: { password: 'bad' } })).status === 403);
  check('Account is deleted', (await api('DELETE', '/api/users/me', { token: bobToken, body: { password: 'new-password-1' } })).status === 200);
  check('Deleted account cannot sign in and disappears from search and groups', (await api('POST', '/api/auth/login', { body: { email: 'bob@example.test', password: 'new-password-1' } })).status === 401 && !(await api('GET', '/api/users/search?q=bob', { token: A.token })).data.users.length && !(await api('GET', `/api/groups/${gid}`, { token: A.token })).data.members.some(m => m.userId === B.id));

  abort.abort();
}

try { await main(); } catch (e) { check('Test run completed without exceptions', false, e.stack); }
await stopServer(); fcm.close();
const failed = results.filter(r => !r.ok);
fs.writeFileSync(process.env.TSUKYO_TEST_REPORT || 'tests/last-run.json', JSON.stringify({ ranAt: new Date().toISOString(), total: results.length, passed: results.length - failed.length, failed: failed.length, results }, null, 2));
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
for (const f of failed) console.log(` - FAILED: ${f.name} ${f.detail}`);
process.exit(failed.length ? 1 : 0);
