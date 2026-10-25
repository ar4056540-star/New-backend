# Backend automated test report

Run at: 2026-10-24T04:07:56.688Z
Result: **121/121 checks passed**

How it was run: `tests/api.test.mjs` starts the real server bundle with a temporary data directory and a local fake Firebase endpoint, then exercises the HTTP API with several accounts. In the sandbox used for this run there was no network access, so `express` could not be installed; the server was run against a minimal Express-compatible stub (routing, JSON body parsing, SSE). **Re-run the suite against the real dependencies with `npm run build && npm run test:api` before deploying.**

Synthetic data only: media bytes are a real 1x1 PNG and random bytes labelled `video/mp4`. The reel stream/range tests prove the server stores and serves the file correctly; they do not prove a decodable video plays on a device.

| # | Check | Result |
|---|---|---|
| 1 | Registration returns 201 and a session token | PASS |
| 2 | New accounts are NOT verified and have an empty bio | PASS |
| 3 | Registration response never exposes password data | PASS |
| 4 | Duplicate email is rejected (409) | PASS |
| 5 | Weak password is rejected (400) | PASS |
| 6 | Protected endpoint without a token returns 401 | PASS |
| 7 | Wrong password returns 401 | PASS |
| 8 | Login with correct credentials works | PASS |
| 9 | Another user's profile does not expose the email address | PASS |
| 10 | Own profile (auth/me) includes the email | PASS |
| 11 | Repeated failed logins are throttled (429) | PASS |
| 12 | Edit profile: other users are forbidden (403) | PASS |
| 13 | Edit profile persists bio and website | PASS |
| 14 | Image upload returns 201 and a media URL | PASS |
| 15 | Uploaded image can be retrieved byte-for-byte | PASS |
| 16 | Media supports HTTP range requests (206) | PASS |
| 17 | Unsupported upload type is rejected (415) | PASS |
| 18 | Image cannot be uploaded to the reels folder (415) | PASS |
| 19 | Upload without authentication is rejected (401) | PASS |
| 20 | Post with media the user does not own is rejected (400) | PASS |
| 21 | Post with an external URL is rejected (400) | PASS |
| 22 | Post creation returns 201 with real media and zero engagement | PASS |
| 23 | Following feed is empty before following anyone | PASS |
| 24 | Explore feed (scope=all) shows the post to Bob | PASS |
| 25 | Follow is idempotent; follower count is derived from records | PASS |
| 26 | Account B sees Account A's post in the following feed | PASS |
| 27 | Follow created exactly one notification for Alice | PASS |
| 28 | Cannot follow yourself (400) | PASS |
| 29 | Like returns the authoritative count | PASS |
| 30 | Like created an unread notification with a correct count | PASS |
| 31 | Comment is created and the count is authoritative | PASS |
| 32 | Reply is stored with its parent | PASS |
| 33 | Bob received a reply notification | PASS |
| 34 | A third user cannot delete someone else's comment (403) | PASS |
| 35 | Empty comment is rejected (400) | PASS |
| 36 | Bookmark is saved and listed | PASS |
| 37 | Search finds the post by hashtag | PASS |
| 38 | User search finds Alice by partial username | PASS |
| 39 | After a server restart the session, post, like, comment and bookmark persist | PASS |
| 40 | Notification preferences can be changed | PASS |
| 41 | Disabled like notifications are not created | PASS |
| 42 | Mark all notifications as read | PASS |
| 43 | Report a post | PASS |
| 44 | Invalid report target is rejected (400) | PASS |
| 45 | Report is persisted once | PASS |
| 46 | Story is created with a 24 hour expiry | PASS |
| 47 | Story is visible to Bob and not yet viewed | PASS |
| 48 | Story viewer list shows Bob to the owner only | PASS |
| 49 | Only the owner can delete a story | PASS |
| 50 | Expired stories no longer appear | PASS |
| 51 | Video upload is accepted for reels | PASS |
| 52 | A reel cannot reference an image upload (400) | PASS |
| 53 | Reel is created with the default audio label | PASS |
| 54 | Bob sees the reel in the Reels feed | PASS |
| 55 | The reel video streams with range support | PASS |
| 56 | Reel, like and comment persist after restart | PASS |
| 57 | New conversation has no placeholder message | PASS |
| 58 | Message is saved; a retry with the same clientId does not duplicate it | PASS |
| 59 | Bob sees the conversation with an unread count of 1 and a summary badge | PASS |
| 60 | Message summary endpoint matches | PASS |
| 61 | Alice has no unread messages | PASS |
| 62 | Bob can read the message | PASS |
| 63 | Marking a conversation as seen clears the unread badge | PASS |
| 64 | Alice sees the message marked as read | PASS |
| 65 | Bob can reply with a quoted message | PASS |
| 66 | Alice can read the reply | PASS |
| 67 | A third account cannot read the conversation (403) | PASS |
| 68 | A third account cannot send into the conversation (403) | PASS |
| 69 | Empty messages are rejected (400) | PASS |
| 70 | Message history is paginated | PASS |
| 71 | Only the sender can delete a direct message | PASS |
| 72 | Messages persist after restart | PASS |
| 73 | Device token registration works and reports push is enabled | PASS |
| 74 | The server signed a valid Firebase JWT | PASS |
| 75 | Bob's device received a push for the new direct message with the conversation id | PASS |
| 76 | The sender does not receive a push for their own message | PASS |
| 77 | Real-time events reached the recipient only | PASS |
| 78 | Group is created with three members and a creator | PASS |
| 79 | Group needs at least one other member (400) | PASS |
| 80 | Alice sees the group in the inbox as a group | PASS |
| 81 | Bob sees the group in the inbox as a group | PASS |
| 82 | Carol sees the group in the inbox as a group | PASS |
| 83 | Dave (outside the group) cannot read group messages (403) | PASS |
| 84 | Dave cannot open group info (403) | PASS |
| 85 | Dave cannot send to the group (403) | PASS |
| 86 | Bob and Carol read the group message with the sender shown | PASS |
| 87 | Group push uses the group name as the title for both members | PASS |
| 88 | Group unread count is tracked per member | PASS |
| 89 | Bob replies and Carol can read the reply | PASS |
| 90 | Marking the group as seen reduces Bob's badge but not Carol's | PASS |
| 91 | A muted member gets no push and the badge excludes the muted group | PASS |
| 92 | Members cannot rename the group (403) | PASS |
| 93 | Members cannot add members while the setting is admins-only (403) | PASS |
| 94 | Only admins can remove members (403 for Bob) | PASS |
| 95 | After promotion Bob can rename the group | PASS |
| 96 | An admin cannot remove the group creator (403) | PASS |
| 97 | Only the creator can remove admins | PASS |
| 98 | An admin can add Dave, who then reads the group | PASS |
| 99 | A new member does not see messages from before they joined | PASS |
| 100 | A member who leaves can no longer read the group (403) | PASS |
| 101 | The creator can remove a member, who loses access | PASS |
| 102 | Group events are recorded as system messages | PASS |
| 103 | Admin can delete another member's group message | PASS |
| 104 | Group details, members and admins persist after restart | PASS |
| 105 | An unregistered device token is removed automatically | PASS |
| 106 | After logout the session is invalid (401) and no push is sent to that device | PASS |
| 107 | A blocked user cannot see the blocker's profile (404) | PASS |
| 108 | A blocked user is hidden from search results | PASS |
| 109 | Blocked users cannot start a conversation (403) | PASS |
| 110 | Blocked users cannot see the blocker's posts in Explore | PASS |
| 111 | The blocked list is returned | PASS |
| 112 | Unblocking restores access | PASS |
| 113 | Only the owner can delete a post (403 for Bob) | PASS |
| 114 | Owner deletes the post | PASS |
| 115 | Deleted post is gone from the feed and its media is removed | PASS |
| 116 | Deleted post comments and favorites are removed | PASS |
| 117 | Change password rejects a wrong current password (403) | PASS |
| 118 | Change password signs out other sessions and old password stops working | PASS |
| 119 | Account deletion requires the correct password (403) | PASS |
| 120 | Account is deleted | PASS |
| 121 | Deleted account cannot sign in and disappears from search and groups | PASS |
