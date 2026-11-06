<div align="center">

# Auka — server

**A tiny self-hosted, end-to-end encrypted messenger for a family or a small group.**

Text · copy-exact code blocks · photos and files · a "ring their phone" button

![Java 25](https://img.shields.io/badge/Java-25-orange) ![SQLite](https://img.shields.io/badge/storage-SQLite-blue) ![RAM](https://img.shields.io/badge/RAM-~80%20MB-green) ![E2E](https://img.shields.io/badge/encryption-end--to--end-purple)

</div>

---

## Why

- **Private by design.** Messages, photos and files are encrypted on the phone. The server only stores ciphertext and never holds a key that opens it.
- **Small.** One container with an embedded database. It idles at about 80 MB of RAM and fits a 1 vCPU / 1 GB VPS with room to spare.
- **Simple to run.** One `.env`, one `docker compose up`. No message queue, no external database, no cloud services required.

## Features

- 1:1 chats, one permanent chat per person, with delete for both sides and read receipts
- Contacts by `@nickname`; there is no user directory and no search
- Code blocks that copy back byte for byte, which matters for VPN keys and configs
- Photos and files up to 15 MB, encrypted, with an expiry date
- **Ring**: makes the other person's phone play a sound for 20 seconds. Cooldowns are 3 minutes, then 10 minutes, so it can't be spammed
- Email confirmation and a login code (optional), invite codes, blocking
- Push notifications through APNs. The text is decrypted on the device, so Apple sees only ciphertext

## Run your own server

You need a Linux host with Docker and the compose plugin, about 300 MB of free RAM, and TCP port 8443 open. Any small VPS or a home server will do.

```sh
git clone https://github.com/Vainstel/auka-backend.git && cd auka-backend
cp .env.example .env           # set PUBLIC_HOST and INVITE_CODE at least
docker compose up -d --build
docker compose logs | grep -A1 fingerprint
```

In the app, enter the server's IP (or domain). The app shows the certificate fingerprint: compare it with the one from the log and tap "Trust". Then register and share the invite code with the people you want on the server.

Push notifications work out of the box through the public Auka relays; nothing to configure. Everything lives in the `auka-data` volume and survives restarts and upgrades.

To upgrade: `git pull && docker compose up -d --build`.

## Configuration

Everything is set through environment variables, usually in `.env`. No secret is stored in this repository.

| Variable | Default | What it does |
|---|---|---|
| `PUBLIC_HOST` | (required) | IP or domain clients use. It goes into the self-signed certificate on first start. |
| `SERVER_NAME` | `Auka` | Name shown in the app. |
| `INVITE_CODE` | (none) | Code needed to register. Without it the server refuses to start, unless `ALLOW_OPEN_REGISTRATION=true`. |
| `ALLOW_OPEN_REGISTRATION` | `false` | Lets anyone who finds the server register. The app hides the invite field then. |
| `TLS_MODE` | `self-signed` | `off` when a reverse proxy in front terminates TLS. |
| `TRUST_PROXY` | `false` | Take the client IP from `X-Forwarded-For`. Only behind your own proxy. |
| `HOST_BIND` / `HOST_PORT` | `0.0.0.0` / `8443` | Where the port is published. Use `127.0.0.1` behind a local proxy, or a LAN IP for a home-only server. |
| `SMTP_HOST` `SMTP_PORT` `SMTP_USERNAME` `SMTP_PASSWORD` | (none), `587` | When `SMTP_HOST` is set, registration and every login need a code from email. Without it, login and password are enough. STARTTLS is mandatory. |
| `MAIL_FROM` / `MAIL_FROM_NAME` | (none) / `Auka` | Sender of those emails. |
| `MAIL_MAX_PER_DAY` | `200` | Ceiling on registration and reset emails. Login codes don't count. |
| `PUSH_RELAYS` | public Auka relays | Where pushes go. Relays are tried in order: `https://host`, or `https://ip:port\|<cert SHA-256>` for a self-signed one. `none` turns push off. |
| `APNS_KEY_BASE64` `APNS_KEY_ID` `APNS_TEAM_ID` `APNS_TOPIC` | (none) | Your own Apple key: the server pushes directly and skips the relays. Only useful if you publish your own build of the app. |
| `APNS_CRITICAL_RING` | `false` | Rings break through silent mode. Only after Apple grants the Critical Alerts entitlement. |
| `MESSAGE_RETENTION_DAYS` | `0` | Delete messages from the server after N days. `0` keeps them. |
| `FILE_STORAGE_MB` | `500` | Total room for photos and files. When it's full, uploads fail and the app says to try later. |
| `FILE_TTL_HOURS` | `168` | How long a file lives on the server (7 days). The app shows the hours left on every file. |
| `FILE_MAX_MB` | `15` | Largest single file. |

## Push notifications and the relay

Only the holder of the app's Apple key can send it notifications, and a self-hosted server doesn't have that key. So pushes go through **relays**: small stateless services that hold the key. They work automatically, with nothing to configure.

```
phone ──register token──▶ relay ──handle──▶ phone ──handle──▶ your server
your server ──"wake handle: message #42"──▶ relay ──▶ Apple ──▶ phone
phone's extension ──fetch #42──▶ your server, then decrypts it locally
```

- **What a relay sees:** an opaque handle plus "message" or "ring", the sender's and message's ids (meaningless outside your server), and an unread count. No text, no ciphertext, no names.
- **What it doesn't see:** your server never learns the phone's real push token. The handle is that token encrypted with the relay's secret, so the relay keeps no database.
- **Abuse:** handles can't be forged, so nobody can push to arbitrary devices. Every handle is rate-limited, and rings are capped.
- **Failover:** the server tries the relays in order: 5 s for the first, 15 s for each backup. If one is down or blocked, the next takes over. All relays share one `RELAY_SECRET`, so handles work on any of them.

### Running a relay

Only for whoever publishes the app:

```sh
cp .env.relay.example .env.relay                 # RELAY_SECRET, APNS_* and PUBLIC_HOST
docker compose -f compose.relay.yaml up -d --build
docker compose -f compose.relay.yaml logs | grep -A1 fingerprint
```

A relay reachable by bare IP uses a self-signed certificate. Servers reach it pinned to its fingerprint (`https://ip:8444|<fingerprint>`). Plain `http://` works too, but then anyone who can watch that traffic can reuse handles to make phones ring.

## Security

- **End-to-end encryption.**
  - Each account has an X25519 key pair.
  - Messages use ChaCha20-Poly1305 with a key per conversation.
  - Each file gets its own random key, which travels only inside the encrypted message.
- **The password never leaves the device.** PBKDF2 (600k rounds) turns it into a login key and a separate key that wraps the private key. Clients refuse weaker settings even if a server asks for them.
- **Key pinning.**
  - A contact's key is pinned on first contact, and a changed key stops sending until the user confirms it.
  - Users can compare safety numbers in person.
  - The server's TLS certificate is pinned on first connection.
- **Abuse limits:**
  - Rate limits on every endpoint.
  - Strangers can send only a few messages until the other person replies.
  - Email codes have a per-day guess limit that survives restarts.
  - Daily send quota, capped sync pages, connection limit.
- **Hardened container:** non-root, read-only filesystem, all capabilities dropped, a memory limit.

What the server *can* see: who talks to whom and when, approximate sizes, nicknames, display names and emails. There is no forward secrecy: a stolen private key opens that account's history. The full protocol is in [docs/protocol.md](docs/protocol.md).

## Development

```sh
./gradlew test                                    # JDK 25
pip install cryptography
python tools/e2e.py https://127.0.0.1:8443        # real crypto against a running server
python tools/e2e.py --vectors vectors.json        # test vectors for client implementations
```

Stack: Java 25, Javalin 7, SQLite, plain JDBC, JDK HTTP/2 for APNs. Migrations are the `MIGRATIONS` array in `Db.java`. All routes are under `/api/v1` and require a session, except those listed in `Api.PUBLIC`.

## Limits

- 1:1 chats only, about 64,000 characters per message.
- A forgotten password means a new key: old messages become unreadable, by design.
- Android push (FCM) isn't implemented yet; it will go through the same relays.
