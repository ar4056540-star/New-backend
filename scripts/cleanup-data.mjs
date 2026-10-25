#!/usr/bin/env node
// Safe data audit and cleanup for the JSON data store.
// Default is a DRY RUN that only reports. Nothing is changed unless --apply is passed.
//   node scripts/cleanup-data.mjs --data-dir /var/data                 (report only)
//   node scripts/cleanup-data.mjs --data-dir /var/data --apply         (backup, then remove orphaned records)
// Optional flags (each needs --apply):
//   --clear-auto-verification   Remove the "verified" badge that the old registration endpoint granted to everyone.
//   --clear-default-bio         Clear the old default bio "Living the VYBE lifestyle." where the user never changed it.
// Accounts are NEVER deleted by this script. Suspicious accounts are only listed for manual review.
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const flag = n => args.includes(n);
const valueOf = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const dataDir = path.resolve(valueOf('--data-dir') || process.env.DATA_DIR || path.join(process.cwd(), 'backend', 'data'));
const apply = flag('--apply');
const names = ['users', 'posts', 'reels', 'stories', 'comments', 'conversations', 'messages', 'notifications', 'follows', 'favorites', 'sessions', 'media', 'reactions', 'blocks', 'reports', 'devices', 'app-locks'];
const store = {}; const original = {};
for (const n of names) { try { store[n] = JSON.parse(fs.readFileSync(path.join(dataDir, `${n}.json`), 'utf8')); } catch { store[n] = []; } original[n] = JSON.stringify(store[n]); }

const report = { dataDir, mode: apply ? 'APPLY' : 'DRY RUN', counts: {}, orphans: {}, flagged: {}, changes: {} };
for (const n of names) report.counts[n] = store[n].length;

const userIds = new Set(store.users.map(u => u.userId));
const postIds = new Set(store.posts.map(p => p.postId));
const reelIds = new Set(store.reels.map(r => r.reelId));
const contentIds = new Set([...postIds, ...reelIds]);
const convIds = new Set(store.conversations.map(c => c.conversationId));
const mediaFiles = new Set(fs.existsSync(path.join(dataDir, 'media')) ? fs.readdirSync(path.join(dataDir, 'media')) : []);

const orphanRules = {
  posts: x => !userIds.has(x.ownerId),
  reels: x => !userIds.has(x.ownerId),
  stories: x => !userIds.has(x.ownerId),
  comments: x => !userIds.has(x.authorId) || !(x.targetType === 'posts' ? postIds : reelIds).has(x.targetId),
  reactions: x => !userIds.has(x.userId) || !contentIds.has(x.contentId),
  favorites: x => !userIds.has(x.userId),
  follows: x => !userIds.has(x.userId) || !userIds.has(x.targetUserId),
  notifications: x => !userIds.has(x.userId),
  messages: x => !convIds.has(x.conversationId),
  sessions: x => !userIds.has(x.userId),
  devices: x => !userIds.has(x.userId),
  blocks: x => !userIds.has(x.blockerId) || !userIds.has(x.blockedId),
  media: x => !userIds.has(x.ownerId) || !mediaFiles.has(x.storedName),
};
for (const [n, rule] of Object.entries(orphanRules)) report.orphans[n] = store[n].filter(rule).length;
report.orphans.conversationsWithMissingParticipants = store.conversations.filter(c => c.participantIds.some(p => !userIds.has(p))).length;

const referencedMedia = new Set(store.media.map(m => m.storedName));
report.flagged.unreferencedMediaFiles = [...mediaFiles].filter(f => !referencedMedia.has(f) && !f.endsWith('.part') && f !== '.gitkeep');
report.flagged.autoVerifiedUsers = store.users.filter(u => u.isVerified === true && !u.verificationReviewedAt).map(u => u.username);
report.flagged.defaultBioUsers = store.users.filter(u => /Living the VYBE lifestyle/.test(u.bio || '')).map(u => u.username);
const suspicious = /^(demo|test|sample|dummy|fake|user\d+|vybe|admin)/i;
const fakeDomain = /@(example\.(com|org|net)|test\.com|mailinator\.com)$/i;
report.flagged.possibleDemoAccounts = store.users.filter(u => suspicious.test(u.username) || fakeDomain.test(u.email || '')).map(u => ({ userId: u.userId, username: u.username, email: u.email, posts: store.posts.filter(p => p.ownerId === u.userId).length }));
report.flagged.note = 'Flagged accounts are not removed automatically. Review them manually before taking any action.';

if (apply) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupDir = path.join(dataDir, 'backups', stamp);
  fs.mkdirSync(backupDir, { recursive: true });
  for (const n of names) if (fs.existsSync(path.join(dataDir, `${n}.json`))) fs.copyFileSync(path.join(dataDir, `${n}.json`), path.join(backupDir, `${n}.json`));
  report.backupDir = backupDir;
  for (const [n, rule] of Object.entries(orphanRules)) {
    if (n === 'media') continue; // media records are only reported; files are never deleted by this script
    const kept = store[n].filter(x => !rule(x));
    if (kept.length !== store[n].length) { report.changes[`removed orphaned ${n}`] = store[n].length - kept.length; store[n] = kept; }
  }
  if (flag('--clear-auto-verification')) {
    let count = 0; for (const u of store.users) if (u.isVerified === true && !u.verificationReviewedAt) { u.isVerified = false; u.verificationReviewedAt = new Date().toISOString(); count++; }
    report.changes['cleared auto-granted verification badges'] = count;
  }
  if (flag('--clear-default-bio')) {
    let count = 0; for (const u of store.users) if (/^✨ Living the VYBE lifestyle\.$/.test(u.bio || '')) { u.bio = ''; count++; }
    report.changes['cleared default bios'] = count;
  }
  for (const n of names) if (JSON.stringify(store[n]) !== original[n]) fs.writeFileSync(path.join(dataDir, `${n}.json`), JSON.stringify(store[n], null, 2));
}
console.log(JSON.stringify(report, null, 2));
