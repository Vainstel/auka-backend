# Auka protocol

Every client (iOS now, Android later) must implement exactly this. `tools/e2e.py` is a working reference and generates the test vectors that the clients check themselves against.

All byte strings in JSON are standard base64. HKDF is HKDF-SHA256 with an empty salt.

## Password and account keys

The password never leaves the device.

1. `master = PBKDF2-HMAC-SHA256(password as NFC UTF-8, kdfSalt, kdfIterations, 32 bytes)`
2. `authKey = HKDF(master, info="auka-auth-v1", 32)`: sent to the server, which hashes it again.
3. `wrapKey = HKDF(master, info="auka-wrap-v1", 32)`: never sent.

The account has one X25519 identity. The private key is stored on the server only in wrapped form:

`wrappedPrivateKey = nonce(12) || ChaCha20-Poly1305(wrapKey, nonce, privateKey, aad="auka-identity-v1" || publicKey) || tag(16)`

After unwrapping, the client derives the public key and refuses the login if it differs from the account's `publicKey`.

## Messages

`messageKey = HKDF(X25519(myPrivate, peerPublic), info="auka-msg-v1" || lower(pubA, pubB) || higher(pubA, pubB), 32)`, comparing keys bytewise.

Plaintext is `{"k":"text"|"code","t":"..."}` as UTF-8, padded with trailing spaces to the next multiple of 256 bytes so the ciphertext length hides the exact message length. Text inside `t` is never altered: code blocks must copy back byte for byte.

The envelope is a JSON string that the server stores untouched:

`{"v":1,"s":senderPublic,"r":recipientPublic,"n":nonce(12),"c":ciphertext||tag(16)}`

AAD is the UTF-8 of `auka-msg-v1|<senderId>|<recipientId>|<clientId>`, so the server cannot re-attribute a message or replay it into another chat.

To decrypt, take the peer's key from the envelope (`s` for incoming, `r` for outgoing) and accept it only if the device trusts that key for that peer. An unknown key means the message is shown as unverified until the user accepts it.

## Files and photos

1. The sender makes a random 32-byte `fileKey` and encrypts the file: `blob = nonce(12) || ChaCha20-Poly1305(fileKey, nonce, file, aad="auka-file-v1") || tag(16)`.
2. `POST /files?recipientId=<id>` with the blob as a raw body (`application/octet-stream`). The answer is `{id, size, expiresAt}`.
3. The sender sends a normal message with `"fileId"` and this content inside the envelope:
   `{"k":"image"|"file","t":"","f":{"id","key","name","size","mime","exp"}}`, where `key` is `fileKey` in base64 and `exp` is `expiresAt`.
4. The recipient gets the key from the decrypted message, downloads `GET /files/{id}` and decrypts.

So only the two people in the chat can open a file. The server stores ciphertext and doesn't know the name, type or content.

Only the uploader and that recipient can download a file, and a message can only reference a file its sender uploaded for that same recipient. Deleting the message deletes the file. After `FILE_TTL_HOURS` the server deletes it: downloads then get `410 file_expired`. Uploads over `FILE_MAX_MB` get `413 file_too_large`. When `FILE_STORAGE_MB` is used up, uploads get `507 storage_full`. `/server-info` reports `maxFileBytes` and `fileTtlHours`.

## Push

Pushes contain no message content. A message push carries `type:"message"`, `senderId` and `messageId`. The app's notification extension fetches `GET /messages/{id}` from its own server and decrypts it on the device. A ring push carries `type:"ring"`, `senderId` and `ringId`.

`/server-info` returns `pushMode`:
- `direct`: the server has its own Apple key. The app sends `PUT /me/push-token {token, sandbox}`.
- `relay`: the app sends its token to a relay from `relays` with `POST /relay/v1/register {token, sandbox}` and gets back `{handle}`. It then sends `PUT /me/push-token {handle}`. A relay with a `pin` is trusted only with that exact certificate.
- `none`: no pushes.

The server wakes a device with `POST /relay/v1/push {handle, kind, senderId, messageId|ringId, badge}`. It tries relays in order and moves to the next only when one is unreachable or failing. A `410` means the handle is dead and is dropped.

## Key trust

Clients pin each peer's public key on first sight and keep the pins across logout, so a forced re-login can't reset them. When the server later reports a different key (the peer reset their password, or the server is lying), the client stops sending and asks the user to confirm. Old trusted keys are kept so that history stays readable.

Safety number: `SHA-256(lower(pubA, pubB) || higher(pubA, pubB))`. Take the first 30 bytes as 6 groups of 5 bytes; each group is a big-endian integer mod 100000, printed as 5 digits. Both people see the same number and can compare it in person.

## What the server can and cannot see

It can see who talks to whom, when, and the approximate message size, plus nicknames, display names and emails. It cannot see message text. Whoever steals the database can attack a password offline: each guess costs the 600,000 client iterations, checked against `wrappedPrivateKey`. So the password's strength matters. Clients refuse `kdfIterations` below 600,000 or a salt other than 16 bytes, so a hostile server can't make guessing cheaper. There is no forward secrecy: anyone who obtains a private key can read that account's past messages.

## Sync

`GET /sync?after=<cursor>` returns everything that changed for the user: messages, tombstones (`deleted: true`, no envelope) and read markers. Repeat while `hasMore`. WebSocket events carry no content: `{"type":"sync"}` means "call sync", and `{"type":"ring",...}` starts the ring screen. Authenticate a socket by sending `{"token":"..."}` as the first message.

## Ring

`POST /rings/{userId}` rings the other person's devices for 20 seconds. The first ring is free, the next needs 3 minutes, every later one 10 minutes, and an hour of quiet resets the ladder. Too early gets `429 ring_cooldown` with `nextAllowedAt`. The callee must have added the caller as a contact or written to them, otherwise `403 ring_not_allowed`.

## Connection security

Default deployment is HTTPS with a self-signed certificate. On first connection the app shows the certificate's SHA-256 fingerprint, and from then on accepts only that certificate. Compare it with the fingerprint in the server log.
