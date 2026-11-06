package io.vainslab.auka;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.config.JavalinConfig;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/** The whole HTTP surface. Deny by default: every route needs a session unless listed in PUBLIC. */
final class Api {
    private static final Logger log = LoggerFactory.getLogger(Api.class);

    static final String PREFIX = "/api/v1";
    private static final Set<String> PUBLIC = Set.of(
            PREFIX + "/server-info", PREFIX + "/ws",
            PREFIX + "/auth/prelogin", PREFIX + "/auth/register", PREFIX + "/auth/register/verify",
            PREFIX + "/auth/register/resend", PREFIX + "/auth/login", PREFIX + "/auth/login/verify",
            PREFIX + "/auth/reset/request", PREFIX + "/auth/reset/confirm");

    private static final Pattern EMAIL = Pattern.compile("^[^\\s@\"<>,;:\\\\()\\[\\]]{1,64}@[A-Za-z0-9.-]{1,190}\\.[A-Za-z]{2,}$");
    private static final Pattern NICKNAME = Pattern.compile("^[a-z][a-z0-9_]{2,31}$");
    private static final Pattern APNS_TOKEN = Pattern.compile("^[0-9a-fA-F]{32,256}$");
    private static final int DEFAULT_KDF_ITERATIONS = 600_000;
    private static final int MIN_KDF_ITERATIONS = 600_000;
    private static final int MAX_KDF_ITERATIONS = 10_000_000;
    private static final int MAX_ENVELOPE_CHARS = 200_000;
    private static final int AVATAR_COLORS = 12;
    private static final int SYNC_PAGE = 200;
    private static final int SYNC_PAGE_CHARS = 2_000_000;
    private static final long DAILY_SEND_CHARS = 50_000_000L;
    private static final int CODE_FAILURES_PER_DAY = 20;
    // Room for the nonce, tag and the client's padding on top of the plaintext limit.
    private static final long FILE_OVERHEAD = 64 * 1024;
    private static final long CODE_TTL = 10 * 60_000L;
    private static final int CODE_ATTEMPTS = 5;
    private static final long MINUTE = 60_000L;
    private static final long HOUR = 60 * MINUTE;
    private static final String CODE_REGISTER = "register";
    private static final String CODE_LOGIN = "login";
    private static final String CODE_RESET = "reset";

    record Session(String tokenHash, String userId) {
    }

    private record Credentials(String id, byte[] hash, byte[] salt) {
    }

    private final Config config;
    private final Db db;
    private final ObjectMapper json;
    private final Hub hub;
    private final Mailer mailer;
    private final Pusher pusher;
    private final RateLimiter limiter;
    private final FileStore files;
    private final RelayClient relays;
    private final byte[] serverSecret;
    private final byte[] dummySalt;
    private final AtomicInteger mailsToday = new AtomicInteger();
    private volatile LocalDate mailDay = LocalDate.now(ZoneOffset.UTC);

    Api(Config config, Db db, ObjectMapper json, Hub hub, Mailer mailer, Pusher pusher, RateLimiter limiter) {
        this.config = config;
        this.db = db;
        this.json = json;
        this.hub = hub;
        this.mailer = mailer;
        this.pusher = pusher;
        this.limiter = limiter;
        this.files = new FileStore(config.dataDir().resolve("files"));
        this.relays = new RelayClient(RelayClient.parseAll(config.pushRelays()), json);
        this.serverSecret = db.serverSecret();
        this.dummySalt = Secrets.hmac(serverSecret, "dummy-salt");
    }

    void register(JavalinConfig c) {
        var r = c.routes;
        r.before(PREFIX + "/*", ctx -> {
            if (ctx.method().name().equals("OPTIONS")) return;
            ctx.header("Cache-Control", "no-store");
            if (PUBLIC.contains(ctx.path())) return;
            Session s = authenticate(ctx.header("Authorization"));
            ctx.attribute("session", s);
            limiter.check("user:" + s.userId(), 600, MINUTE);
        });

        r.get(PREFIX + "/server-info", this::serverInfo);
        r.post(PREFIX + "/auth/prelogin", this::prelogin);
        r.post(PREFIX + "/auth/register", this::registerUser);
        r.post(PREFIX + "/auth/register/verify", this::registerVerify);
        r.post(PREFIX + "/auth/register/resend", this::registerResend);
        r.post(PREFIX + "/auth/login", this::login);
        r.post(PREFIX + "/auth/login/verify", this::loginVerify);
        r.post(PREFIX + "/auth/reset/request", this::resetRequest);
        r.post(PREFIX + "/auth/reset/confirm", this::resetConfirm);
        r.post(PREFIX + "/auth/logout", this::logout);
        r.post(PREFIX + "/auth/logout-others", this::logoutOthers);

        r.get(PREFIX + "/me", ctx -> send(ctx, me(session(ctx).userId())));
        r.patch(PREFIX + "/me", this::updateMe);
        r.post(PREFIX + "/me/delete", this::deleteMe);
        r.post(PREFIX + "/me/password", this::changePassword);
        r.put(PREFIX + "/me/push-token", this::setPushToken);
        r.delete(PREFIX + "/me/push-token", this::clearPushToken);

        r.get(PREFIX + "/users/by-nickname/{nickname}", this::userByNickname);
        r.get(PREFIX + "/contacts", this::listContacts);
        r.post(PREFIX + "/contacts", this::addContact);
        r.delete(PREFIX + "/contacts/{id}", this::removeContact);
        r.get(PREFIX + "/blocks", this::listBlocks);
        r.put(PREFIX + "/blocks/{id}", this::block);
        r.delete(PREFIX + "/blocks/{id}", this::unblock);

        r.get(PREFIX + "/chats", this::listChats);
        r.post(PREFIX + "/chats/{id}/read", this::markRead);
        r.post(PREFIX + "/messages", this::sendMessage);
        r.get(PREFIX + "/messages/{id}", this::getMessage);
        r.delete(PREFIX + "/messages/{id}", this::deleteMessage);
        r.get(PREFIX + "/sync", this::sync);
        r.post(PREFIX + "/files", this::uploadFile);
        r.get(PREFIX + "/files/{id}", this::downloadFile);

        r.get(PREFIX + "/rings/{id}", this::ringStatus);
        r.post(PREFIX + "/rings/{id}", this::ring);
    }

    // --- server & auth ---

    private void serverInfo(Context ctx) {
        limiter.check("ip:info:" + ip(ctx), 120, MINUTE);
        Map<String, Object> info = new HashMap<>();
        info.put("name", config.serverName());
        info.put("version", 1);
        info.put("emailVerification", config.emailVerification());
        info.put("inviteRequired", config.inviteCode() != null);
        info.put("pushEnabled", config.apnsEnabled() || relays.enabled());
        // With its own Apple key the server pushes directly; otherwise the app registers with a relay.
        info.put("pushMode", config.apnsEnabled() ? "direct" : relays.enabled() ? "relay" : "none");
        info.put("relays", relays.targets().stream().map(RelayClient.Target::describe).toList());
        info.put("kdfIterations", DEFAULT_KDF_ITERATIONS);
        info.put("maxFileBytes", config.fileMaxBytes());
        info.put("fileTtlHours", config.fileTtlHours());
        send(ctx, info);
    }

    /** Unknown emails get a stable fake salt, so this endpoint cannot be used to probe accounts. */
    private void prelogin(Context ctx) {
        limiter.check("ip:prelogin:" + ip(ctx), 60, 5 * MINUTE);
        String email = email(body(ctx));
        var real = db.one("SELECT kdf_salt, kdf_iterations FROM users WHERE email=? AND verified=1",
                rs -> Map.<String, Object>of("kdfSalt", rs.getString(1), "kdfIterations", rs.getInt(2)), email);
        send(ctx, real.orElseGet(() -> {
            byte[] fake = java.util.Arrays.copyOf(Secrets.hmac(serverSecret, "fake-salt|" + email), 16);
            return Map.of("kdfSalt", Base64.getEncoder().encodeToString(fake), "kdfIterations", DEFAULT_KDF_ITERATIONS);
        }));
    }

    private void registerUser(Context ctx) {
        limiter.check("ip:register:" + ip(ctx), 10, HOUR);
        JsonNode b = body(ctx);
        if (config.inviteCode() != null
                && !Secrets.constantTimeEquals(config.inviteCode(), optText(b, "inviteCode", ""))) {
            throw new ApiError(403, "invalid_invite");
        }
        String email = email(b);
        String nickname = nickname(text(b, "nickname", 32));
        String displayName = displayName(text(b, "displayName", 200));
        byte[] authKey = bytes(b, "authKey", 32);
        KeyMaterial keys = keyMaterial(b);
        String publicKey = encodedBytes(b, "publicKey", 32);
        byte[] authSalt = Secrets.randomBytes(16);
        byte[] authHash = Secrets.hashAuthKey(authKey, authSalt);
        long now = System.currentTimeMillis();
        String id = UUID.randomUUID().toString();
        int color = Math.floorMod(id.hashCode(), AVATAR_COLORS);

        boolean silentlyIgnored = db.tx(() -> {
            // Nickname first and regardless of the email, so this answer can't reveal who has an account.
            if (db.exists("SELECT 1 FROM users WHERE nickname=? AND (verified=1 OR email<>?)", nickname, email)) {
                throw new ApiError(409, "nickname_taken");
            }
            var existing = db.one("SELECT id, verified FROM users WHERE email=?",
                    rs -> Map.entry(rs.getString(1), rs.getInt(2) == 1), email);
            if (existing.isPresent() && existing.get().getValue()) {
                // With email codes an attacker learns nothing: same answer, and no code goes out.
                if (config.emailVerification()) return true;
                throw new ApiError(409, "email_taken");
            }
            // A code already sent must not confirm whatever registration replaces this one.
            existing.ifPresent(e -> {
                db.update("DELETE FROM users WHERE id=?", e.getKey());
                db.update("DELETE FROM email_codes WHERE email=? AND purpose=?", email, CODE_REGISTER);
            });
            db.update("""
                    INSERT INTO users (id, email, nickname, display_name, avatar_color, auth_hash, auth_salt,
                        kdf_salt, kdf_iterations, public_key, wrapped_private_key, verified, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    id, email, nickname, displayName, color, authHash, authSalt, keys.salt(), keys.iterations(),
                    publicKey, keys.wrappedPrivateKey(), config.emailVerification() ? 0 : 1, now);
            return false;
        });

        if (config.emailVerification()) {
            if (!silentlyIgnored) issueCode(email, CODE_REGISTER);
            send(ctx, Map.of("status", "code_required"));
        } else {
            send(ctx, newSession(id, deviceName(b)));
        }
    }

    private void registerVerify(Context ctx) {
        limiter.check("ip:verify:" + ip(ctx), 30, 10 * MINUTE);
        JsonNode b = body(ctx);
        String email = email(b);
        byte[] authKey = bytes(b, "authKey", 32);
        // The code only confirms the registration of whoever knows this password.
        var pending = db.one("SELECT id, auth_hash, auth_salt FROM users WHERE email=? AND verified=0",
                rs -> new Credentials(rs.getString(1), rs.getBytes(2), rs.getBytes(3)), email);
        byte[] actual = Secrets.hashAuthKey(authKey, pending.map(Credentials::salt).orElse(dummySalt));
        if (pending.isEmpty() || !Secrets.constantTimeEquals(actual, pending.get().hash())) {
            throw new ApiError(400, "invalid_code");
        }
        String id = pending.get().id();
        checkCode(email, CODE_REGISTER, text(b, "code", 12));
        db.update("UPDATE users SET verified=1 WHERE id=?", id);
        send(ctx, newSession(id, deviceName(b)));
    }

    private void registerResend(Context ctx) {
        limiter.check("ip:resend:" + ip(ctx), 10, 10 * MINUTE);
        String email = email(body(ctx));
        if (db.exists("SELECT 1 FROM users WHERE email=? AND verified=0", email)) issueCode(email, CODE_REGISTER);
        send(ctx, Map.of("status", "ok"));
    }

    /** Only failures count, per email and IP, so a stranger's bad guesses can't lock the owner out. */
    private String checkLoginPassword(Context ctx, String email, byte[] authKey) {
        String local = "fail:login:" + email + ":" + ip(ctx);
        String global = "fail:login:" + email;
        if (limiter.isOver(local, 10, 15 * MINUTE) || limiter.isOver(global, 300, HOUR)) {
            throw new ApiError(429, "rate_limited", Map.of("retryAfterSeconds", 900));
        }
        try {
            return checkPassword(email, authKey);
        } catch (ApiError e) {
            limiter.hit(local, 15 * MINUTE);
            limiter.hit(global, HOUR);
            throw e;
        }
    }

    private void login(Context ctx) {
        limiter.check("ip:login:" + ip(ctx), 30, 15 * MINUTE);
        JsonNode b = body(ctx);
        String email = email(b);
        String id = checkLoginPassword(ctx, email, bytes(b, "authKey", 32));
        if (config.emailVerification()) {
            issueCode(email, CODE_LOGIN);
            send(ctx, Map.of("status", "code_required"));
        } else {
            send(ctx, newSession(id, deviceName(b)));
        }
    }

    private void loginVerify(Context ctx) {
        limiter.check("ip:login:" + ip(ctx), 30, 15 * MINUTE);
        JsonNode b = body(ctx);
        String email = email(b);
        String id = checkLoginPassword(ctx, email, bytes(b, "authKey", 32));
        checkCode(email, CODE_LOGIN, text(b, "code", 12));
        send(ctx, newSession(id, deviceName(b)));
    }

    /** Reset gives the account a new key pair: the old history stays unreadable, by design. */
    private void resetRequest(Context ctx) {
        requireMail();
        limiter.check("ip:reset:" + ip(ctx), 10, HOUR);
        String email = email(body(ctx));
        if (db.exists("SELECT 1 FROM users WHERE email=? AND verified=1", email)) issueCode(email, CODE_RESET);
        send(ctx, Map.of("status", "ok"));
    }

    private void resetConfirm(Context ctx) {
        requireMail();
        limiter.check("ip:reset:" + ip(ctx), 10, HOUR);
        JsonNode b = body(ctx);
        String email = email(b);
        byte[] authKey = bytes(b, "authKey", 32);
        KeyMaterial keys = keyMaterial(b);
        String publicKey = encodedBytes(b, "publicKey", 32);
        checkCode(email, CODE_RESET, text(b, "code", 12));
        byte[] salt = Secrets.randomBytes(16);
        byte[] hash = Secrets.hashAuthKey(authKey, salt);
        String id = db.one("SELECT id FROM users WHERE email=? AND verified=1", rs -> rs.getString(1), email)
                .orElseThrow(() -> new ApiError(400, "invalid_code"));
        db.tx(() -> {
            db.update("""
                    UPDATE users SET auth_hash=?, auth_salt=?, kdf_salt=?, kdf_iterations=?, public_key=?, wrapped_private_key=?
                    WHERE id=?""", hash, salt, keys.salt(), keys.iterations(), publicKey, keys.wrappedPrivateKey(), id);
            db.update("DELETE FROM sessions WHERE user_id=?", id);
            return null;
        });
        hub.closeAll(id);
        send(ctx, Map.of("status", "ok"));
    }

    private void logout(Context ctx) {
        Session s = session(ctx);
        db.update("DELETE FROM sessions WHERE token_hash=?", s.tokenHash());
        hub.closeSession(s.userId(), s.tokenHash());
        ctx.status(204);
    }

    private void logoutOthers(Context ctx) {
        Session s = session(ctx);
        db.update("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", s.userId(), s.tokenHash());
        hub.closeOthers(s.userId(), s.tokenHash());
        ctx.status(204);
    }

    // --- account ---

    private void updateMe(Context ctx) {
        Session s = session(ctx);
        JsonNode b = body(ctx);
        if (b.hasNonNull("displayName")) {
            db.update("UPDATE users SET display_name=? WHERE id=?", displayName(text(b, "displayName", 200)), s.userId());
        }
        if (b.hasNonNull("avatarColor")) {
            int color = b.path("avatarColor").asInt(-1);
            if (color < 0 || color >= AVATAR_COLORS) throw new ApiError(400, "invalid_request");
            db.update("UPDATE users SET avatar_color=? WHERE id=?", color, s.userId());
        }
        if (b.hasNonNull("nickname")) {
            String nickname = nickname(text(b, "nickname", 32));
            db.tx(() -> {
                if (db.exists("SELECT 1 FROM users WHERE nickname=? AND id<>?", nickname, s.userId())) {
                    throw new ApiError(409, "nickname_taken");
                }
                return db.update("UPDATE users SET nickname=? WHERE id=?", nickname, s.userId());
            });
        }
        send(ctx, me(s.userId()));
    }

    private void deleteMe(Context ctx) {
        Session s = session(ctx);
        limiter.check("user:sensitive:" + s.userId(), 10, 15 * MINUTE);
        checkPasswordById(s.userId(), bytes(body(ctx), "authKey", 32));
        db.update("DELETE FROM users WHERE id=?", s.userId());
        hub.closeAll(s.userId());
        ctx.status(204);
    }

    private void changePassword(Context ctx) {
        Session s = session(ctx);
        limiter.check("user:sensitive:" + s.userId(), 10, 15 * MINUTE);
        JsonNode b = body(ctx);
        checkPasswordById(s.userId(), bytes(b, "currentAuthKey", 32));
        byte[] newAuthKey = bytes(b, "authKey", 32);
        KeyMaterial keys = keyMaterial(b);
        byte[] salt = Secrets.randomBytes(16);
        byte[] hash = Secrets.hashAuthKey(newAuthKey, salt);
        db.tx(() -> {
            db.update("UPDATE users SET auth_hash=?, auth_salt=?, kdf_salt=?, kdf_iterations=?, wrapped_private_key=? WHERE id=?",
                    hash, salt, keys.salt(), keys.iterations(), keys.wrappedPrivateKey(), s.userId());
            db.update("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", s.userId(), s.tokenHash());
            return null;
        });
        hub.closeOthers(s.userId(), s.tokenHash());
        ctx.status(204);
    }

    private void setPushToken(Context ctx) {
        Session s = session(ctx);
        JsonNode b = body(ctx);
        if (b.hasNonNull("handle")) {
            String handle = text(b, "handle", 400);
            if (!handle.matches("^[A-Za-z0-9_-]+$")) throw new ApiError(400, "invalid_request");
            db.tx(() -> {
                db.update("UPDATE sessions SET push_handle=NULL WHERE push_handle=?", handle);
                return db.update("UPDATE sessions SET push_handle=?, apns_token=NULL WHERE token_hash=?", handle, s.tokenHash());
            });
            ctx.status(204);
            return;
        }
        String token = text(b, "token", 256);
        if (!APNS_TOKEN.matcher(token).matches()) throw new ApiError(400, "invalid_request");
        db.tx(() -> {
            // A phone that switched accounts must stop receiving the old account's pushes.
            db.update("UPDATE sessions SET apns_token=NULL WHERE apns_token=?", token);
            return db.update("UPDATE sessions SET apns_token=?, apns_sandbox=? WHERE token_hash=?",
                    token, b.path("sandbox").asBoolean(false) ? 1 : 0, s.tokenHash());
        });
        ctx.status(204);
    }

    private void clearPushToken(Context ctx) {
        db.update("UPDATE sessions SET apns_token=NULL, push_handle=NULL WHERE token_hash=?", session(ctx).tokenHash());
        ctx.status(204);
    }

    // --- people ---

    /** Exact match only and rate limited: there is deliberately no way to browse or search users. */
    private void userByNickname(Context ctx) {
        Session s = session(ctx);
        limiter.check("user:lookup:" + s.userId(), 30, MINUTE);
        String nickname = ctx.pathParam("nickname").toLowerCase(java.util.Locale.ROOT);
        if (!NICKNAME.matcher(nickname).matches()) throw new ApiError(404, "user_not_found");
        send(ctx, db.one(PROFILE + " WHERE nickname=? AND verified=1", Api::profile, nickname)
                .orElseThrow(() -> new ApiError(404, "user_not_found")));
    }

    private void listContacts(Context ctx) {
        send(ctx, Map.of("contacts", db.query(PROFILE_COLUMNS_U + """
                 FROM contacts c JOIN users u ON u.id = c.contact_id
                WHERE c.owner_id=? ORDER BY u.display_name COLLATE NOCASE""", Api::profile, session(ctx).userId())));
    }

    private void addContact(Context ctx) {
        Session s = session(ctx);
        String id = uuid(text(body(ctx), "userId", 40));
        requireOtherUser(s, id);
        db.update("INSERT OR IGNORE INTO contacts (owner_id, contact_id, created_at) VALUES (?,?,?)",
                s.userId(), id, System.currentTimeMillis());
        send(ctx, db.one(PROFILE + " WHERE id=?", Api::profile, id).orElseThrow());
    }

    private void removeContact(Context ctx) {
        db.update("DELETE FROM contacts WHERE owner_id=? AND contact_id=?", session(ctx).userId(), uuid(ctx.pathParam("id")));
        ctx.status(204);
    }

    private void listBlocks(Context ctx) {
        send(ctx, Map.of("blocks", db.query(PROFILE_COLUMNS_U + """
                 FROM blocks b JOIN users u ON u.id = b.blocked_id
                WHERE b.owner_id=? ORDER BY u.display_name COLLATE NOCASE""", Api::profile, session(ctx).userId())));
    }

    private void block(Context ctx) {
        Session s = session(ctx);
        String id = uuid(ctx.pathParam("id"));
        requireOtherUser(s, id);
        db.update("INSERT OR IGNORE INTO blocks (owner_id, blocked_id, created_at) VALUES (?,?,?)",
                s.userId(), id, System.currentTimeMillis());
        ctx.status(204);
    }

    private void unblock(Context ctx) {
        db.update("DELETE FROM blocks WHERE owner_id=? AND blocked_id=?", session(ctx).userId(), uuid(ctx.pathParam("id")));
        ctx.status(204);
    }

    // --- messages ---

    private void listChats(Context ctx) {
        String me = session(ctx).userId();
        send(ctx, Map.of("chats", db.query(PROFILE_COLUMNS_U + """
                 FROM users u WHERE u.id IN (
                    SELECT recipient_id FROM messages WHERE sender_id=?
                    UNION SELECT sender_id FROM messages WHERE recipient_id=?)""", Api::profile, me, me)));
    }

    private void sendMessage(Context ctx) {
        Session s = session(ctx);
        limiter.check("user:send:" + s.userId(), 120, MINUTE);
        JsonNode b = body(ctx);
        String recipient = uuid(text(b, "recipientId", 40));
        String clientId = uuid(text(b, "clientId", 40));
        String envelope = text(b, "envelope", MAX_ENVELOPE_CHARS);
        String fileId = b.hasNonNull("fileId") ? fileUuid(text(b, "fileId", 40)) : null;
        requireOtherUser(s, recipient);
        requireNotBlocked(s.userId(), recipient);
        // A message may only point at a file its sender uploaded for this very recipient.
        if (fileId != null && !db.exists("SELECT 1 FROM files WHERE id=? AND owner_id=? AND recipient_id=?", fileId, s.userId(), recipient)) {
            throw new ApiError(404, "file_not_found");
        }
        if (!ringAllowed(s.userId(), recipient)) {
            // Until the other side answers, a stranger can only knock a few times.
            limiter.check("user:stranger:" + s.userId() + ":" + recipient, 10, 24 * HOUR);
            limiter.check("user:strangers:" + s.userId(), 50, 24 * HOUR);
        }
        long now = System.currentTimeMillis();

        record Saved(long id, long seq, long createdAt, boolean isNew) {
        }
        Saved saved = db.tx(() -> {
            // A retry after a lost response must not create a second copy.
            var dup = db.one("SELECT id, seq, created_at FROM messages WHERE sender_id=? AND client_id=?",
                    rs -> new Saved(rs.getLong(1), rs.getLong(2), rs.getLong(3), false), s.userId(), clientId);
            if (dup.isPresent()) return dup.get();
            long sentToday = db.one("SELECT COALESCE(SUM(LENGTH(envelope)), 0) FROM messages WHERE sender_id=? AND created_at>?",
                    rs -> rs.getLong(1), s.userId(), now - 24 * HOUR).orElse(0L);
            if (sentToday + envelope.length() > DAILY_SEND_CHARS) throw new ApiError(429, "quota_exceeded");
            long seq = db.nextSeq();
            db.update("INSERT INTO messages (seq, sender_id, recipient_id, client_id, envelope, created_at, file_id) VALUES (?,?,?,?,?,?,?)",
                    seq, s.userId(), recipient, clientId, envelope, now, fileId);
            long id = db.one("SELECT last_insert_rowid()", rs -> rs.getLong(1)).orElseThrow();
            return new Saved(id, seq, now, true);
        });

        if (saved.isNew()) {
            hub.poke(recipient);
            hub.poke(s.userId());
            pushMessage(s.userId(), recipient, saved.id(), clientId, envelope);
        }
        send(ctx, Map.of("id", saved.id(), "seq", saved.seq(), "createdAt", saved.createdAt()));
    }

    /** Either participant can delete; the ciphertext is erased, only a tombstone remains. */
    private void deleteMessage(Context ctx) {
        Session s = session(ctx);
        long id;
        try {
            id = Long.parseLong(ctx.pathParam("id"));
        } catch (NumberFormatException e) {
            throw new ApiError(404, "message_not_found");
        }
        var peers = db.tx(() -> {
            var row = db.one("SELECT sender_id, recipient_id, deleted_at, file_id FROM messages WHERE id=? AND (sender_id=? OR recipient_id=?)",
                    rs -> new String[]{rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)}, id, s.userId(), s.userId())
                    .orElseThrow(() -> new ApiError(404, "message_not_found"));
            if (row[2] == null) {
                db.update("UPDATE messages SET envelope=NULL, deleted_at=?, seq=? WHERE id=?", System.currentTimeMillis(), db.nextSeq(), id);
                if (row[3] != null) db.update("DELETE FROM files WHERE id=?", row[3]);
            }
            return row;
        });
        // Deleting the message takes its attachment with it.
        if (peers[3] != null) files.delete(peers[3]);
        hub.poke(peers[0]);
        hub.poke(peers[1]);
        ctx.status(204);
    }

    private void markRead(Context ctx) {
        Session s = session(ctx);
        String peer = uuid(ctx.pathParam("id"));
        long upTo = body(ctx).path("upToId").asLong(0);
        if (upTo <= 0) throw new ApiError(400, "invalid_request");
        boolean changed = db.tx(() -> {
            // Only a message this peer really sent to me can move the marker.
            if (!db.exists("SELECT 1 FROM messages WHERE id=? AND sender_id=? AND recipient_id=?", upTo, peer, s.userId())) {
                throw new ApiError(404, "message_not_found");
            }
            long current = db.one("SELECT up_to_id FROM read_markers WHERE reader_id=? AND peer_id=?",
                    rs -> rs.getLong(1), s.userId(), peer).orElse(0L);
            if (upTo <= current) return false;
            db.update("""
                    INSERT INTO read_markers (reader_id, peer_id, up_to_id, seq) VALUES (?,?,?,?)
                    ON CONFLICT(reader_id, peer_id) DO UPDATE SET up_to_id=excluded.up_to_id, seq=excluded.seq""",
                    s.userId(), peer, upTo, db.nextSeq());
            return true;
        });
        if (changed) {
            hub.poke(peer);
            hub.poke(s.userId());
        }
        ctx.status(204);
    }

    /** One cursor over everything that changed for this user: new messages, tombstones, read markers. */
    private void sync(Context ctx) {
        String me = session(ctx).userId();
        long after;
        try {
            after = Long.parseLong(ctx.queryParamMap().getOrDefault("after", List.of("0")).getFirst());
        } catch (NumberFormatException e) {
            throw new ApiError(400, "invalid_request");
        }
        // Sizes first: a page of huge messages must not be able to exhaust the heap.
        record Meta(long seq, long length) {
        }
        List<Meta> metas = db.query("""
                SELECT seq, COALESCE(LENGTH(envelope), 0) FROM messages
                WHERE seq>? AND (sender_id=? OR recipient_id=?) ORDER BY seq LIMIT ?""",
                rs -> new Meta(rs.getLong(1), rs.getLong(2)), after, me, me, SYNC_PAGE);
        long lastSeq = after;
        long chars = 0;
        boolean truncated = false;
        for (Meta meta : metas) {
            if (lastSeq != after && chars + meta.length() > SYNC_PAGE_CHARS) {
                truncated = true;
                break;
            }
            chars += meta.length();
            lastSeq = meta.seq();
        }
        boolean hasMore = truncated || metas.size() == SYNC_PAGE;
        List<Map<String, Object>> messages = db.query("""
                SELECT id, seq, sender_id, recipient_id, client_id, envelope, created_at, deleted_at FROM messages
                WHERE seq>? AND seq<=? AND (sender_id=? OR recipient_id=?) ORDER BY seq""", rs -> {
            Map<String, Object> m = new HashMap<>();
            m.put("id", rs.getLong(1));
            m.put("seq", rs.getLong(2));
            m.put("senderId", rs.getString(3));
            m.put("recipientId", rs.getString(4));
            m.put("clientId", rs.getString(5));
            m.put("envelope", rs.getString(6));
            m.put("createdAt", rs.getLong(7));
            m.put("deleted", rs.getObject(8) != null);
            return m;
        }, after, lastSeq, me, me);
        long upperSeq = hasMore ? lastSeq : Long.MAX_VALUE;
        List<Map<String, Object>> reads = db.query("""
                SELECT reader_id, peer_id, up_to_id, seq FROM read_markers
                WHERE seq>? AND seq<=? AND (reader_id=? OR peer_id=?) ORDER BY seq""",
                rs -> Map.of("readerId", rs.getString(1), "peerId", rs.getString(2), "upToId", rs.getLong(3), "seq", rs.getLong(4)),
                after, upperSeq, me, me);
        long cursor = after;
        if (!messages.isEmpty()) cursor = Math.max(cursor, (long) messages.getLast().get("seq"));
        if (!reads.isEmpty()) cursor = Math.max(cursor, (long) reads.getLast().get("seq"));
        send(ctx, Map.of("messages", messages, "reads", reads, "cursor", cursor, "hasMore", hasMore));
    }

    // --- files ---

    /** The body is ciphertext made by the client; the server only checks size and storage room. */
    private void uploadFile(Context ctx) {
        Session s = session(ctx);
        limiter.check("user:upload:" + s.userId(), 60, HOUR);
        String recipient = uuid(String.valueOf(ctx.queryParam("recipientId")));
        requireOtherUser(s, recipient);
        requireNotBlocked(s.userId(), recipient);
        if (!ringAllowed(s.userId(), recipient)) {
            limiter.check("user:stranger-files:" + s.userId() + ":" + recipient, 3, 24 * HOUR);
        }
        long max = config.fileMaxBytes() + FILE_OVERHEAD;
        long declared = ctx.req().getContentLengthLong();
        if (declared > max) throw new ApiError(413, "file_too_large", Map.of("maxBytes", config.fileMaxBytes()));
        long reserve = declared > 0 ? declared : max;
        String id = UUID.randomUUID().toString();
        long now = System.currentTimeMillis();
        long expiresAt = now + config.fileTtlHours() * HOUR;
        db.tx(() -> {
            // Room is reserved before the upload starts, so parallel uploads can't overshoot the limit.
            long used = db.one("SELECT COALESCE(SUM(size), 0) FROM files WHERE expires_at>?", rs -> rs.getLong(1), now).orElse(0L);
            if (used + reserve > config.fileStorageBytes()) {
                log.warn("File storage is full: {} of {} bytes used", used, config.fileStorageBytes());
                throw new ApiError(507, "storage_full");
            }
            return db.update("INSERT INTO files (id, owner_id, recipient_id, size, created_at, expires_at) VALUES (?,?,?,?,?,?)",
                    id, s.userId(), recipient, reserve, now, expiresAt);
        });
        long size;
        try {
            size = files.write(id, ctx.req().getInputStream(), max);
        } catch (Exception e) {
            dropFile(id);
            throw new ApiError(400, "upload_failed");
        }
        if (size <= 0) {
            dropFile(id);
            if (size < 0) throw new ApiError(413, "file_too_large", Map.of("maxBytes", config.fileMaxBytes()));
            throw new ApiError(400, "invalid_request");
        }
        db.update("UPDATE files SET size=? WHERE id=?", size, id);
        send(ctx, Map.of("id", id, "size", size, "expiresAt", expiresAt));
    }

    private void downloadFile(Context ctx) {
        Session s = session(ctx);
        String id = fileUuid(ctx.pathParam("id"));
        record Row(long size, long expiresAt) {
        }
        Row row = db.one("SELECT size, expires_at FROM files WHERE id=? AND (owner_id=? OR recipient_id=?)",
                        rs -> new Row(rs.getLong(1), rs.getLong(2)), id, s.userId(), s.userId())
                .orElseThrow(() -> new ApiError(404, "file_not_found"));
        if (row.expiresAt() <= System.currentTimeMillis()) throw new ApiError(410, "file_expired");
        try {
            ctx.header("Content-Length", String.valueOf(row.size()));
            ctx.contentType("application/octet-stream").result(files.open(id));
        } catch (java.io.IOException e) {
            throw new ApiError(404, "file_not_found");
        }
    }

    private void dropFile(String id) {
        db.update("DELETE FROM files WHERE id=?", id);
        files.delete(id);
    }

    /** Expired files go first from the table, then from disk; blobs left without a row are swept too. */
    void cleanupFiles() {
        long now = System.currentTimeMillis();
        for (String id : db.query("SELECT id FROM files WHERE expires_at<=?", rs -> rs.getString(1), now)) dropFile(id);
        for (String id : files.storedIds()) {
            if (!db.exists("SELECT 1 FROM files WHERE id=?", id)) files.delete(id);
        }
    }

    private static String fileUuid(String raw) {
        try {
            return UUID.fromString(raw).toString();
        } catch (IllegalArgumentException e) {
            throw new ApiError(404, "file_not_found");
        }
    }

    // --- rings ---

    private void ringStatus(Context ctx) {
        Session s = session(ctx);
        String peer = uuid(ctx.pathParam("id"));
        long now = System.currentTimeMillis();
        long next = db.one("SELECT streak, last_at FROM rings WHERE caller_id=? AND callee_id=?",
                rs -> RingPolicy.nextAllowedAt(RingPolicy.effectiveStreak(rs.getInt(1), rs.getLong(2), now), rs.getLong(2)),
                s.userId(), peer).orElse(0L);
        send(ctx, Map.of("nextAllowedAt", next, "serverTime", now, "allowed", ringAllowed(s.userId(), peer)));
    }

    /** A stranger cannot make your phone ring: the callee must have added the caller or replied. */
    private boolean ringAllowed(String caller, String callee) {
        return db.exists("SELECT 1 FROM contacts WHERE owner_id=? AND contact_id=?", callee, caller)
                || db.exists("SELECT 1 FROM messages WHERE sender_id=? AND recipient_id=? LIMIT 1", callee, caller);
    }

    private void ring(Context ctx) {
        Session s = session(ctx);
        String callee = uuid(ctx.pathParam("id"));
        requireOtherUser(s, callee);
        requireNotBlocked(s.userId(), callee);
        if (!ringAllowed(s.userId(), callee)) throw new ApiError(403, "ring_not_allowed");
        long now = System.currentTimeMillis();

        long nextAllowedAt = db.tx(() -> {
            var row = db.one("SELECT streak, last_at FROM rings WHERE caller_id=? AND callee_id=?",
                    rs -> new long[]{rs.getInt(1), rs.getLong(2)}, s.userId(), callee);
            int streak = row.map(x -> RingPolicy.effectiveStreak((int) x[0], x[1], now)).orElse(0);
            if (row.isPresent()) {
                long next = RingPolicy.nextAllowedAt(streak, row.get()[1]);
                if (now < next) {
                    throw new ApiError(429, "ring_cooldown", Map.of("nextAllowedAt", next, "serverTime", now));
                }
            }
            int newStreak = streak + 1;
            db.update("""
                    INSERT INTO rings (caller_id, callee_id, last_at, streak) VALUES (?,?,?,?)
                    ON CONFLICT(caller_id, callee_id) DO UPDATE SET last_at=excluded.last_at, streak=excluded.streak""",
                    s.userId(), callee, now, newStreak);
            return RingPolicy.nextAllowedAt(newStreak, now);
        });

        String ringId = UUID.randomUUID().toString();
        Map<String, Object> from = db.one(PROFILE + " WHERE id=?", Api::profile, s.userId()).orElseThrow();
        hub.send(callee, Map.of("type", "ring", "ringId", ringId, "from", from, "seconds", RingPolicy.RING_SECONDS));
        pushRing(callee, ringId, s.userId(), (String) from.get("displayName"));
        send(ctx, Map.of("ringId", ringId, "nextAllowedAt", nextAllowedAt, "serverTime", now, "seconds", RingPolicy.RING_SECONDS));
    }

    // --- push ---

    private void pushMessage(String senderId, String recipient, long messageId, String clientId, String envelope) {
        int badge = db.one("""
                SELECT COUNT(*) FROM messages m
                LEFT JOIN read_markers r ON r.reader_id = m.recipient_id AND r.peer_id = m.sender_id
                WHERE m.recipient_id=? AND m.deleted_at IS NULL AND m.id > COALESCE(r.up_to_id, 0)""",
                rs -> rs.getInt(1), recipient).orElse(0);
        wake(recipient, new Pusher.Push(Relay.messagePayload(senderId, messageId, badge), "m" + messageId),
                Map.of("kind", "message", "senderId", senderId, "messageId", messageId, "badge", badge));
    }

    private void pushRing(String callee, String ringId, String callerId, String callerName) {
        wake(callee, new Pusher.Push(Relay.ringPayload(callerId, ringId, config.apnsCriticalRing()), null),
                Map.of("kind", "ring", "senderId", callerId, "ringId", ringId));
    }

    /** Each device gets the push the way it registered: straight to APNs with our key, or through a relay. */
    private void wake(String userId, Pusher.Push direct, Map<String, Object> relayed) {
        record Device(String token, boolean sandbox, String handle) {
        }
        List<Device> devices = db.query("""
                SELECT apns_token, apns_sandbox, push_handle FROM sessions
                WHERE user_id=? AND (apns_token IS NOT NULL OR push_handle IS NOT NULL)""",
                rs -> new Device(rs.getString(1), rs.getInt(2) == 1, rs.getString(3)), userId);
        for (Device d : devices) {
            if (d.token() != null && config.apnsEnabled()) {
                pusher.send(d.token(), d.sandbox(), direct, dead -> db.update("UPDATE sessions SET apns_token=NULL WHERE apns_token=?", dead));
            } else if (d.handle() != null && relays.enabled()) {
                Map<String, Object> body = new HashMap<>(relayed);
                body.put("handle", d.handle());
                Thread.startVirtualThread(() -> {
                    if (relays.send(body) == RelayClient.Result.GONE) {
                        db.update("UPDATE sessions SET push_handle=NULL WHERE push_handle=?", d.handle());
                    }
                });
            }
        }
    }

    /** One message, for the push extension: it fetches and decrypts the text on the device. */
    private void getMessage(Context ctx) {
        String me = session(ctx).userId();
        long id;
        try {
            id = Long.parseLong(ctx.pathParam("id"));
        } catch (NumberFormatException e) {
            throw new ApiError(404, "message_not_found");
        }
        send(ctx, db.one("""
                SELECT id, sender_id, recipient_id, client_id, envelope, created_at FROM messages
                WHERE id=? AND (sender_id=? OR recipient_id=?) AND deleted_at IS NULL""", rs -> Map.of(
                "id", rs.getLong(1), "senderId", rs.getString(2), "recipientId", rs.getString(3),
                "clientId", rs.getString(4), "envelope", rs.getString(5), "createdAt", rs.getLong(6)), id, me, me)
                .orElseThrow(() -> new ApiError(404, "message_not_found")));
    }

    // --- helpers ---

    Session authenticate(String header) {
        if (header == null || !header.startsWith("Bearer ")) throw new ApiError(401, "unauthorized");
        return authenticateToken(header.substring(7).trim());
    }

    Session authenticateToken(String token) {
        if (token.isEmpty() || token.length() > 100) throw new ApiError(401, "unauthorized");
        String hash = Secrets.sha256Hex(token);
        long now = System.currentTimeMillis();
        record Row(String userId, long lastSeen) {
        }
        Row row = db.one("SELECT user_id, last_seen_at FROM sessions WHERE token_hash=?",
                rs -> new Row(rs.getString(1), rs.getLong(2)), hash)
                .orElseThrow(() -> new ApiError(401, "unauthorized"));
        if (now - row.lastSeen() > MINUTE) db.update("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", now, hash);
        return new Session(hash, row.userId());
    }

    private Session session(Context ctx) {
        return ctx.attribute("session");
    }

    private Map<String, Object> newSession(String userId, String device) {
        String token = Secrets.newToken();
        long now = System.currentTimeMillis();
        db.update("INSERT INTO sessions (token_hash, user_id, device_name, created_at, last_seen_at) VALUES (?,?,?,?,?)",
                Secrets.sha256Hex(token), userId, device, now, now);
        String wrapped = db.one("SELECT wrapped_private_key FROM users WHERE id=?", rs -> rs.getString(1), userId).orElseThrow();
        return Map.of("status", "ok", "token", token, "user", me(userId), "wrappedPrivateKey", wrapped);
    }

    private Map<String, Object> me(String userId) {
        return db.one("SELECT id, nickname, display_name, avatar_color, public_key, email FROM users WHERE id=?", rs -> {
            Map<String, Object> m = profile(rs);
            m.put("email", rs.getString(6));
            return m;
        }, userId).orElseThrow(() -> new ApiError(401, "unauthorized"));
    }

    private static final String PROFILE_COLUMNS = "SELECT id, nickname, display_name, avatar_color, public_key";
    private static final String PROFILE = PROFILE_COLUMNS + " FROM users";
    // Trailing space: text blocks appended after it may lose their leading indentation.
    private static final String PROFILE_COLUMNS_U = "SELECT u.id, u.nickname, u.display_name, u.avatar_color, u.public_key ";

    private static Map<String, Object> profile(java.sql.ResultSet rs) throws java.sql.SQLException {
        Map<String, Object> m = new HashMap<>();
        m.put("id", rs.getString(1));
        m.put("nickname", rs.getString(2));
        m.put("displayName", rs.getString(3));
        m.put("avatarColor", rs.getInt(4));
        m.put("publicKey", rs.getString(5));
        return m;
    }

    private String checkPassword(String email, byte[] authKey) {
        var cred = db.one("SELECT id, auth_hash, auth_salt FROM users WHERE email=? AND verified=1",
                rs -> new Credentials(rs.getString(1), rs.getBytes(2), rs.getBytes(3)), email);
        // Unknown emails burn the same hashing time, so timing does not reveal who has an account.
        byte[] actual = Secrets.hashAuthKey(authKey, cred.map(Credentials::salt).orElse(dummySalt));
        if (cred.isEmpty() || !Secrets.constantTimeEquals(actual, cred.get().hash())) {
            throw new ApiError(401, "invalid_credentials");
        }
        return cred.get().id();
    }

    private void checkPasswordById(String userId, byte[] authKey) {
        var cred = db.one("SELECT id, auth_hash, auth_salt FROM users WHERE id=?",
                rs -> new Credentials(rs.getString(1), rs.getBytes(2), rs.getBytes(3)), userId)
                .orElseThrow(() -> new ApiError(401, "unauthorized"));
        if (!Secrets.constantTimeEquals(Secrets.hashAuthKey(authKey, cred.salt()), cred.hash())) {
            throw new ApiError(401, "invalid_credentials");
        }
    }

    private void issueCode(String email, String purpose) {
        LocalDate today = LocalDate.now(ZoneOffset.UTC);
        if (!today.equals(mailDay)) {
            mailDay = today;
            mailsToday.set(0);
        }
        try {
            limiter.check("email:send:" + purpose + ":" + email, 5, HOUR);
        } catch (ApiError e) {
            return;
        }
        // Login codes follow a correct password, so strangers burning the cap must not stop them.
        if (!CODE_LOGIN.equals(purpose) && mailsToday.incrementAndGet() > config.mailMaxPerDay()) {
            log.warn("Daily mail cap reached; code not sent");
            return;
        }
        String code = Secrets.newCode();
        db.update("""
                INSERT INTO email_codes (email, purpose, code_hash, expires_at, attempts) VALUES (?,?,?,?,0)
                ON CONFLICT(email, purpose) DO UPDATE SET code_hash=excluded.code_hash, expires_at=excluded.expires_at, attempts=0""",
                email, purpose, codeHash(email, purpose, code), System.currentTimeMillis() + CODE_TTL);
        mailer.sendCode(email, code);
    }

    private void checkCode(String email, String purpose, String code) {
        long day = System.currentTimeMillis() / (24 * HOUR);
        boolean ok = db.tx(() -> {
            record Row(byte[] hash, long expiresAt, int attempts) {
            }
            // Kept in the database: a restart must not hand out fresh guesses.
            int failures = db.one("SELECT count FROM code_failures WHERE email=? AND purpose=? AND day=?",
                    rs -> rs.getInt(1), email, purpose, day).orElse(0);
            if (failures >= CODE_FAILURES_PER_DAY) return false;
            var row = db.one("SELECT code_hash, expires_at, attempts FROM email_codes WHERE email=? AND purpose=?",
                    rs -> new Row(rs.getBytes(1), rs.getLong(2), rs.getInt(3)), email, purpose);
            if (row.isEmpty() || row.get().expiresAt() < System.currentTimeMillis() || row.get().attempts() >= CODE_ATTEMPTS
                    || !Secrets.constantTimeEquals(row.get().hash(), codeHash(email, purpose, code))) {
                db.update("UPDATE email_codes SET attempts=attempts+1 WHERE email=? AND purpose=?", email, purpose);
                db.update("""
                        INSERT INTO code_failures (email, purpose, day, count) VALUES (?,?,?,1)
                        ON CONFLICT(email, purpose) DO UPDATE SET count = CASE WHEN day=excluded.day THEN count+1 ELSE 1 END, day=excluded.day""",
                        email, purpose, day);
                return false;
            }
            db.update("DELETE FROM email_codes WHERE email=? AND purpose=?", email, purpose);
            return true;
        });
        if (!ok) throw new ApiError(400, "invalid_code");
    }

    private byte[] codeHash(String email, String purpose, String code) {
        return Secrets.hmac(serverSecret, email + "|" + purpose + "|" + code);
    }

    private void requireMail() {
        if (!config.emailVerification()) throw new ApiError(404, "feature_disabled");
    }

    private void requireOtherUser(Session s, String id) {
        if (id.equals(s.userId())) throw new ApiError(400, "invalid_request");
        if (!db.exists("SELECT 1 FROM users WHERE id=? AND verified=1", id)) throw new ApiError(404, "user_not_found");
    }

    private void requireNotBlocked(String a, String b) {
        if (db.exists("SELECT 1 FROM blocks WHERE (owner_id=? AND blocked_id=?) OR (owner_id=? AND blocked_id=?)", a, b, b, a)) {
            throw new ApiError(403, "blocked");
        }
    }

    void checkWsUpgrade(Context ctx) {
        limiter.check("ip:ws:" + ip(ctx), 60, MINUTE);
    }

    private String ip(Context ctx) {
        if (config.trustProxy()) {
            String xff = ctx.header("X-Forwarded-For");
            // The last hop is the one our own proxy appended; anything before it is client-supplied.
            if (xff != null && !xff.isBlank()) return xff.substring(xff.lastIndexOf(',') + 1).trim();
        }
        return ctx.req().getRemoteAddr();
    }

    private void send(Context ctx, Object value) {
        try {
            ctx.contentType("application/json").result(json.writeValueAsString(value));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private JsonNode body(Context ctx) {
        try {
            JsonNode node = json.readTree(ctx.bodyAsBytes());
            if (node == null || !node.isObject()) throw new ApiError(400, "invalid_request");
            return node;
        } catch (java.io.IOException e) {
            throw new ApiError(400, "invalid_request");
        }
    }

    private static String text(JsonNode b, String field, int maxLength) {
        JsonNode n = b.get(field);
        if (n == null || !n.isTextual() || n.textValue().isEmpty() || n.textValue().length() > maxLength) {
            throw new ApiError(400, "invalid_request", Map.of("field", field));
        }
        return n.textValue();
    }

    private static String optText(JsonNode b, String field, String fallback) {
        JsonNode n = b.get(field);
        return n != null && n.isTextual() ? n.textValue() : fallback;
    }

    private static String email(JsonNode b) {
        String email = text(b, "email", 254).trim().toLowerCase(java.util.Locale.ROOT);
        if (!EMAIL.matcher(email).matches()) throw new ApiError(400, "invalid_email");
        return email;
    }

    private static String nickname(String raw) {
        String nickname = raw.toLowerCase(java.util.Locale.ROOT);
        if (!NICKNAME.matcher(nickname).matches()) throw new ApiError(400, "invalid_nickname");
        return nickname;
    }

    private static String displayName(String raw) {
        String name = raw.strip();
        // Format characters include text-direction overrides, which can disguise a name; ZWJ stays for emoji.
        if (name.isEmpty() || name.length() > 64 || name.chars().anyMatch(c -> Character.isISOControl(c)
                || (Character.getType(c) == Character.FORMAT && c != 0x200D))) {
            throw new ApiError(400, "invalid_display_name");
        }
        return name;
    }

    private static String deviceName(JsonNode b) {
        String name = optText(b, "deviceName", "device").strip();
        if (name.isEmpty() || name.chars().anyMatch(Character::isISOControl)) return "device";
        return name.length() > 64 ? name.substring(0, 64) : name;
    }

    private static String uuid(String raw) {
        try {
            return UUID.fromString(raw).toString();
        } catch (IllegalArgumentException e) {
            throw new ApiError(404, "user_not_found");
        }
    }

    private static byte[] bytes(JsonNode b, String field, int length) {
        try {
            byte[] out = Base64.getDecoder().decode(text(b, field, length * 2 + 8));
            if (out.length != length) throw new ApiError(400, "invalid_request", Map.of("field", field));
            return out;
        } catch (IllegalArgumentException e) {
            throw new ApiError(400, "invalid_request", Map.of("field", field));
        }
    }

    private static String encodedBytes(JsonNode b, String field, int length) {
        return Base64.getEncoder().encodeToString(bytes(b, field, length));
    }

    private record KeyMaterial(String salt, int iterations, String wrappedPrivateKey) {
    }

    private static KeyMaterial keyMaterial(JsonNode b) {
        int iterations = b.path("kdfIterations").asInt(0);
        if (iterations < MIN_KDF_ITERATIONS || iterations > MAX_KDF_ITERATIONS) {
            throw new ApiError(400, "invalid_request", Map.of("field", "kdfIterations"));
        }
        String wrapped = text(b, "wrappedPrivateKey", 256);
        try {
            Base64.getDecoder().decode(wrapped);
        } catch (IllegalArgumentException e) {
            throw new ApiError(400, "invalid_request", Map.of("field", "wrappedPrivateKey"));
        }
        return new KeyMaterial(encodedBytes(b, "kdfSalt", 16), iterations, wrapped);
    }

    /** Housekeeping, run hourly. */
    void cleanup() {
        long now = System.currentTimeMillis();
        db.update("DELETE FROM users WHERE verified=0 AND created_at<?", now - 24 * HOUR);
        db.update("DELETE FROM email_codes WHERE expires_at<?", now);
        db.update("DELETE FROM code_failures WHERE day<?", now / (24 * HOUR));
        db.update("DELETE FROM sessions WHERE last_seen_at<?", now - 180 * 24 * HOUR);
        if (config.messageRetentionDays() > 0) {
            db.update("DELETE FROM messages WHERE created_at<?", now - config.messageRetentionDays() * 24 * HOUR);
        }
        limiter.prune(25 * HOUR);
    }
}
