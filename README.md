# Auka backend

Server for Auka, a very simple end-to-end encrypted messenger for a family or a small group: text, easy-to-copy code blocks, and a "ring their phone" button. Self-hosted, one container, about 80 MB of RAM with the database inside.

The server stores only ciphertext. Message keys live on the devices. See [docs/protocol.md](docs/protocol.md) for what it can and cannot see.

## Run it

Needs Docker on any small VPS.

```sh
cp .env.example .env     # set PUBLIC_HOST to the server's IP or domain
docker compose up -d --build
docker compose logs | grep -A1 fingerprint
```

In the app, enter the IP and compare the fingerprint it shows with the one from the log. Open port 8443 in the firewall. Data stays in the `auka-data` volume across restarts and upgrades.

## Configuration

Everything is set through `.env`; `.env.example` lists each option. No secret is ever stored in this repository.

- **Email codes**: on only when `SMTP_HOST` is set. Then registration needs a code from email and each login needs one too. Without SMTP, login and password are enough.
- **Invite code**: `INVITE_CODE` is required, so that strangers who find the address can't register. To run open anyway, set `ALLOW_OPEN_REGISTRATION=true`.
- **Push notifications**: set the `APNS_*` values, using a key from the Apple developer account that publishes the app. Without them, messages and rings arrive only while the app is open.
- **Domain instead of IP**: set `PUBLIC_HOST` to the domain. To use a real certificate, put a reverse proxy in front, with `TLS_MODE=off`, `TRUST_PROXY=true` and `HOST_BIND=127.0.0.1`.

## Development

```sh
./gradlew test                                     # needs JDK 25
python tools/e2e.py https://127.0.0.1:8443         # real crypto against a running server; pip install cryptography
```

Stack: Java 25, Javalin 7, SQLite, plain JDBC. Migrations are the `MIGRATIONS` array in `Db.java`.

## Limits

- 1:1 chats only.
- Up to about 64,000 characters per message.
- No forward secrecy: a stolen private key opens that account's past messages. The key is stored on the server only under a password-derived key, so choose a long password.
- Forgetting the password means losing access to old messages, by design.
