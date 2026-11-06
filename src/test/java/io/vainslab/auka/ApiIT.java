package io.vainslab.auka;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApiIT {
    @TempDir
    Path dir;

    private final ObjectMapper json = Main.jsonMapper();
    private final HttpClient http = HttpClient.newHttpClient();
    private final Map<String, String> codes = new ConcurrentHashMap<>();
    private final List<Pusher.Push> pushes = new ArrayList<>();
    private Javalin app;
    private Db db;
    private int port;
    private final Map<String, String> extraEnv = new HashMap<>();

    private void boot(boolean mail, String invite) throws Exception {
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        Map<String, String> env = new HashMap<>();
        env.put("PORT", String.valueOf(port));
        env.put("DATA_DIR", dir.toString());
        if (mail) env.put("SMTP_HOST", "smtp.test");
        if (invite != null) env.put("INVITE_CODE", invite);
        env.put("APNS_KEY_BASE64", "x");
        env.put("APNS_KEY_ID", "x");
        env.put("APNS_TEAM_ID", "x");
        env.put("APNS_TOPIC", "x");
        env.putAll(extraEnv);
        db = new Db(dir);
        app = Main.start(Config.fromEnv(env), db, json, codes::put, (t, sb, push, dead) -> pushes.add(push));
    }

    @AfterEach
    void stop() {
        if (app != null) app.stop();
        if (db != null) db.close();
    }

    private record Res(int status, JsonNode body) {
    }

    private Res call(String method, String path, String token, Object body) throws Exception {
        var b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1" + path));
        if (token != null) b.header("Authorization", "Bearer " + token);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(json.writeValueAsBytes(body)));
        var r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        return new Res(r.statusCode(), r.body().isEmpty() ? json.nullNode() : json.readTree(r.body()));
    }

    private static String b64(int n, int fill) {
        byte[] a = new byte[n];
        java.util.Arrays.fill(a, (byte) fill);
        return Base64.getEncoder().encodeToString(a);
    }

    private Map<String, Object> registration(String email, String nick, int key) {
        Map<String, Object> m = new HashMap<>();
        m.put("email", email);
        m.put("nickname", nick);
        m.put("displayName", nick.toUpperCase());
        m.put("authKey", b64(32, key));
        m.put("kdfSalt", b64(16, key));
        m.put("kdfIterations", 600000);
        m.put("publicKey", b64(32, key + 1));
        m.put("wrappedPrivateKey", b64(60, key + 2));
        return m;
    }

    private record User(String id, String token) {
    }

    private User user(String nick) throws Exception {
        Res r = call("POST", "/auth/register", null, registration(nick + "@test.io", nick, nick.hashCode() & 0x7f));
        assertEquals(200, r.status(), r.body().toString());
        return new User(r.body().path("user").path("id").asText(), r.body().path("token").asText());
    }

    private String sendMsg(User from, User to, String envelope) throws Exception {
        Res r = call("POST", "/messages", from.token(), Map.of("recipientId", to.id(), "clientId", UUID.randomUUID().toString(), "envelope", envelope));
        assertEquals(200, r.status(), r.body().toString());
        return r.body().path("id").asText();
    }

    private Res upload(User from, User to, byte[] data) throws Exception {
        var req = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/files?recipientId=" + to.id()))
                .header("Authorization", "Bearer " + from.token())
                .POST(HttpRequest.BodyPublishers.ofByteArray(data)).build();
        var r = http.send(req, HttpResponse.BodyHandlers.ofString());
        return new Res(r.statusCode(), r.body().isEmpty() ? json.nullNode() : json.readTree(r.body()));
    }

    private HttpResponse<byte[]> download(User who, String id) throws Exception {
        var req = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/files/" + id))
                .header("Authorization", "Bearer " + who.token()).GET().build();
        return http.send(req, HttpResponse.BodyHandlers.ofByteArray());
    }

    @Test
    void filesReachOnlyTheTwoPeople() throws Exception {
        boot(false, null);
        User a = user("alice"), b = user("bobby"), c = user("carol");
        call("POST", "/contacts", b.token(), Map.of("userId", a.id()));
        byte[] data = new byte[300_000];
        new java.util.Random(1).nextBytes(data);
        Res up = upload(a, b, data);
        assertEquals(200, up.status(), up.body().toString());
        String id = up.body().path("id").asText();
        long ttl = up.body().path("expiresAt").asLong() - System.currentTimeMillis();
        assertTrue(Math.abs(ttl - 168 * 3_600_000L) < 60_000);
        assertTrue(java.util.Arrays.equals(data, download(b, id).body()));
        assertTrue(java.util.Arrays.equals(data, download(a, id).body()));
        assertEquals(404, download(c, id).statusCode());

        // Only the uploader can attach the file, and only in a message to that same person.
        assertEquals(404, call("POST", "/messages", c.token(), Map.of("recipientId", b.id(), "clientId", UUID.randomUUID().toString(), "envelope", "x", "fileId", id)).status());
        Res msg = call("POST", "/messages", a.token(), Map.of("recipientId", b.id(), "clientId", UUID.randomUUID().toString(), "envelope", "x", "fileId", id));
        assertEquals(200, msg.status());
        assertEquals(204, call("DELETE", "/messages/" + msg.body().path("id").asText(), b.token(), null).status());
        assertEquals(404, download(a, id).statusCode());
    }

    @Test
    void fileLimitsAndExpiry() throws Exception {
        extraEnv.put("FILE_MAX_MB", "1");
        extraEnv.put("FILE_STORAGE_MB", "2");
        extraEnv.put("FILE_TTL_HOURS", "5");
        boot(false, null);
        User a = user("alice"), b = user("bobby");
        call("POST", "/contacts", b.token(), Map.of("userId", a.id()));
        assertEquals(5, call("GET", "/server-info", null, null).body().path("fileTtlHours").asInt());
        assertEquals(413, upload(a, b, new byte[1_200_000]).status());

        String first = upload(a, b, new byte[900_000]).body().path("id").asText();
        assertEquals(200, upload(a, b, new byte[900_000]).status());
        Res full = upload(a, b, new byte[900_000]);
        assertEquals(507, full.status());
        assertEquals("storage_full", full.body().path("error").asText());

        // An expired file is gone for both sides and no longer takes up room.
        db.update("UPDATE files SET expires_at=? WHERE id=?", System.currentTimeMillis() - 1, first);
        assertEquals(410, download(b, first).statusCode());
        assertEquals(200, upload(a, b, new byte[900_000]).status());
    }

    @Test
    void singleFactorRegistrationAndLogin() throws Exception {
        boot(false, null);
        assertEquals(false, call("GET", "/server-info", null, null).body().path("emailVerification").asBoolean());
        User a = user("alice");
        assertFalse(a.token().isEmpty());
        assertEquals(409, call("POST", "/auth/register", null, registration("alice@test.io", "alice2", 5)).status());
        assertEquals(409, call("POST", "/auth/register", null, registration("other@test.io", "alice", 5)).status());

        int key = "alice".hashCode() & 0x7f;
        Res ok = call("POST", "/auth/login", null, Map.of("email", "ALICE@test.io", "authKey", b64(32, key)));
        assertEquals(200, ok.status());
        assertEquals(b64(60, key + 2), ok.body().path("wrappedPrivateKey").asText());
        assertEquals(401, call("POST", "/auth/login", null, Map.of("email", "alice@test.io", "authKey", b64(32, 99))).status());
    }

    @Test
    void emailCodeFlowDoesNotRevealAccounts() throws Exception {
        boot(true, null);
        Res r = call("POST", "/auth/register", null, registration("bob@test.io", "bobby", 7));
        assertEquals("code_required", r.body().path("status").asText());
        assertEquals(401, call("POST", "/auth/login", null, Map.of("email", "bob@test.io", "authKey", b64(32, 7))).status());

        String good = codes.get("bob@test.io");
        String bad = good.equals("000000") ? "000001" : "000000";
        assertEquals(400, call("POST", "/auth/register/verify", null, Map.of("email", "bob@test.io", "authKey", b64(32, 7), "code", bad)).status());
        // The right code from the wrong person confirms nothing.
        assertEquals(400, call("POST", "/auth/register/verify", null, Map.of("email", "bob@test.io", "authKey", b64(32, 8), "code", good)).status());
        Res verified = call("POST", "/auth/register/verify", null, Map.of("email", "bob@test.io", "authKey", b64(32, 7), "code", good));
        assertEquals(200, verified.status());
        assertNotNull(verified.body().path("token").textValue());
        assertEquals(400, call("POST", "/auth/register/verify", null, Map.of("email", "bob@test.io", "authKey", b64(32, 7), "code", good)).status());

        // Registering a taken email looks exactly like a fresh registration and sends nothing.
        codes.clear();
        Res again = call("POST", "/auth/register", null, registration("bob@test.io", "bobby2", 8));
        assertEquals("code_required", again.body().path("status").asText());
        assertTrue(codes.isEmpty());
        // A nickname that is taken gets the same answer whoever asks, so it cannot confirm whose email it is.
        assertEquals(409, call("POST", "/auth/register", null, registration("bob@test.io", "bobby", 8)).status());
        assertEquals(409, call("POST", "/auth/register", null, registration("other@test.io", "bobby", 8)).status());

        assertEquals("code_required", call("POST", "/auth/login", null, Map.of("email", "bob@test.io", "authKey", b64(32, 7))).body().path("status").asText());
        assertEquals(401, call("POST", "/auth/login/verify", null, Map.of("email", "bob@test.io", "authKey", b64(32, 8), "code", codes.get("bob@test.io"))).status());
        assertEquals(200, call("POST", "/auth/login/verify", null, Map.of("email", "bob@test.io", "authKey", b64(32, 7), "code", codes.get("bob@test.io"))).status());

        JsonNode real = call("POST", "/auth/prelogin", null, Map.of("email", "bob@test.io")).body();
        assertEquals(b64(16, 7), real.path("kdfSalt").asText());
        JsonNode fake1 = call("POST", "/auth/prelogin", null, Map.of("email", "nobody@test.io")).body();
        JsonNode fake2 = call("POST", "/auth/prelogin", null, Map.of("email", "nobody@test.io")).body();
        assertEquals(fake1, fake2);
    }

    @Test
    void codeBurnsAfterTooManyGuesses() throws Exception {
        boot(true, null);
        call("POST", "/auth/register", null, registration("eve@test.io", "evelyn", 9));
        String good = codes.get("eve@test.io");
        String bad = good.equals("000000") ? "000001" : "000000";
        for (int i = 0; i < 5; i++) call("POST", "/auth/register/verify", null, Map.of("email", "eve@test.io", "authKey", b64(32, 9), "code", bad));
        assertEquals(400, call("POST", "/auth/register/verify", null, Map.of("email", "eve@test.io", "authKey", b64(32, 9), "code", good)).status());
    }

    @Test
    void replacingAPendingRegistrationKillsItsCode() throws Exception {
        boot(true, null);
        call("POST", "/auth/register", null, registration("v@test.io", "victim", 10));
        String first = codes.get("v@test.io");
        codes.clear();
        call("POST", "/auth/register", null, registration("v@test.io", "attacker", 11));
        String second = codes.get("v@test.io");
        assertEquals(400, call("POST", "/auth/register/verify", null, Map.of("email", "v@test.io", "authKey", b64(32, 10), "code", first)).status());
        assertEquals(200, call("POST", "/auth/register/verify", null, Map.of("email", "v@test.io", "authKey", b64(32, 11), "code", second)).status());
    }

    @Test
    void strangerResetRequestsDoNotBlockTheOwnersLoginCode() throws Exception {
        boot(true, null);
        call("POST", "/auth/register", null, registration("o@test.io", "owner", 12));
        call("POST", "/auth/register/verify", null, Map.of("email", "o@test.io", "authKey", b64(32, 12), "code", codes.get("o@test.io")));
        for (int i = 0; i < 6; i++) call("POST", "/auth/reset/request", null, Map.of("email", "o@test.io"));
        codes.clear();
        assertEquals("code_required", call("POST", "/auth/login", null, Map.of("email", "o@test.io", "authKey", b64(32, 12))).body().path("status").asText());
        assertNotNull(codes.get("o@test.io"));
    }

    @Test
    void weakKdfIsRefused() throws Exception {
        boot(false, null);
        var m = registration("w@test.io", "weak", 13);
        m.put("kdfIterations", 1000);
        assertEquals(400, call("POST", "/auth/register", null, m).status());
    }

    @Test
    void syncPagesAreBoundedByBytes() throws Exception {
        boot(false, null);
        User a = user("alice"), b = user("bobby");
        call("POST", "/contacts", b.token(), Map.of("userId", a.id()));
        String big = "x".repeat(190_000);
        for (int i = 0; i < 15; i++) sendMsg(a, b, big);
        JsonNode first = call("GET", "/sync", b.token(), null).body();
        assertTrue(first.path("hasMore").asBoolean());
        assertEquals(10, first.path("messages").size());
        JsonNode second = call("GET", "/sync?after=" + first.path("cursor").asLong(), b.token(), null).body();
        assertFalse(second.path("hasMore").asBoolean());
        assertEquals(5, second.path("messages").size());
    }

    @Test
    void strangersAreCappedUntilAnswered() throws Exception {
        boot(false, null);
        User a = user("alice"), b = user("bobby");
        for (int i = 0; i < 10; i++) sendMsg(a, b, "x");
        assertEquals(429, call("POST", "/messages", a.token(), Map.of("recipientId", b.id(), "clientId", UUID.randomUUID().toString(), "envelope", "x")).status());
        sendMsg(b, a, "y");
        sendMsg(a, b, "x");
    }

    @Test
    void disguisedDisplayNamesAreRefused() throws Exception {
        boot(false, null);
        var m = registration("d@test.io", "disguise", 14);
        m.put("displayName", "\u202Eмама");
        assertEquals(400, call("POST", "/auth/register", null, m).status());
    }

    @Test
    void inviteCodeIsEnforced() throws Exception {
        boot(false, "family");
        assertEquals(403, call("POST", "/auth/register", null, registration("a@test.io", "aaaa", 1)).status());
        var m = registration("a@test.io", "aaaa", 1);
        m.put("inviteCode", "family");
        assertEquals(200, call("POST", "/auth/register", null, m).status());
    }

    @Test
    void everythingNeedsAuthExceptPublicPaths() throws Exception {
        boot(false, null);
        for (String[] route : new String[][]{{"GET", "/me"}, {"GET", "/sync"}, {"GET", "/contacts"}, {"GET", "/chats"},
                {"POST", "/messages"}, {"DELETE", "/messages/1"}, {"POST", "/rings/" + UUID.randomUUID()},
                {"GET", "/users/by-nickname/alice"}, {"GET", "/me/"}, {"POST", "/me/delete"}}) {
            assertEquals(401, call(route[0], route[1], null, Map.of()).status(), route[1]);
            assertEquals(401, call(route[0], route[1], "wrong", Map.of()).status(), route[1]);
        }
    }

    @Test
    void outsidersCannotReadOrTouchAChat() throws Exception {
        boot(false, null);
        User a = user("alice"), b = user("bobby"), c = user("carol");
        String id = sendMsg(a, b, "secret-ciphertext");

        assertTrue(call("GET", "/sync", b.token(), null).body().toString().contains("secret-ciphertext"));
        assertTrue(call("GET", "/sync", a.token(), null).body().toString().contains("secret-ciphertext"));
        assertFalse(call("GET", "/sync", c.token(), null).body().toString().contains("secret-ciphertext"));
        assertEquals(0, call("GET", "/chats", c.token(), null).body().path("chats").size());

        assertEquals(404, call("DELETE", "/messages/" + id, c.token(), null).status());
        assertEquals(404, call("POST", "/chats/" + a.id() + "/read", c.token(), Map.of("upToId", Long.parseLong(id))).status());
        assertEquals(204, call("DELETE", "/messages/" + id, b.token(), null).status());
        JsonNode tomb = call("GET", "/sync", a.token(), null).body().path("messages").get(0);
        assertTrue(tomb.path("deleted").asBoolean());
        assertTrue(tomb.path("envelope").isNull());
    }

    @Test
    void syncCursorAndIdempotentSend() throws Exception {
        boot(false, null);
        User a = user("alice"), b = user("bobby");
        String client = UUID.randomUUID().toString();
        Map<String, String> msg = Map.of("recipientId", b.id(), "clientId", client, "envelope", "e1");
        String id1 = call("POST", "/messages", a.token(), msg).body().path("id").asText();
        String id2 = call("POST", "/messages", a.token(), msg).body().path("id").asText();
        assertEquals(id1, id2);

        JsonNode first = call("GET", "/sync", b.token(), null).body();
        assertEquals(1, first.path("messages").size());
        long cursor = first.path("cursor").asLong();
        assertEquals(0, call("GET", "/sync?after=" + cursor, b.token(), null).body().path("messages").size());

        assertEquals(204, call("POST", "/chats/" + a.id() + "/read", b.token(), Map.of("upToId", Long.parseLong(id1))).status());
        JsonNode reads = call("GET", "/sync?after=" + cursor, a.token(), null).body();
        assertEquals(1, reads.path("reads").size());
        assertEquals(b.id(), reads.path("reads").get(0).path("readerId").asText());
    }

    @Test
    void longMessagesPassThrough() throws Exception {
        boot(false, null);
        User a = user("alice"), b = user("bobby");
        String big = "x".repeat(150_000);
        sendMsg(a, b, big);
        assertEquals(big, call("GET", "/sync", b.token(), null).body().path("messages").get(0).path("envelope").asText());
        assertEquals(400, call("POST", "/messages", a.token(),
                Map.of("recipientId", b.id(), "clientId", UUID.randomUUID().toString(), "envelope", "x".repeat(200_001))).status());
    }

    @Test
    void ringCooldownEscalates() throws Exception {
        boot(false, null);
        User a = user("alice"), b = user("bobby");
        // A stranger can't ring: bobby has neither added alice nor written to her.
        assertEquals(403, call("POST", "/rings/" + b.id(), a.token(), null).status());
        call("POST", "/contacts", b.token(), Map.of("userId", a.id()));

        Res first = call("POST", "/rings/" + b.id(), a.token(), null);
        assertEquals(200, first.status());
        long start = first.body().path("serverTime").asLong();
        assertEquals(start + RingPolicy.FIRST_COOLDOWN, first.body().path("nextAllowedAt").asLong());

        Res blocked = call("POST", "/rings/" + b.id(), a.token(), null);
        assertEquals(429, blocked.status());
        assertEquals("ring_cooldown", blocked.body().path("error").asText());

        // Move the clock: the second ring opens after 3 minutes and then needs 10.
        db.update("UPDATE rings SET last_at=? WHERE caller_id=?", System.currentTimeMillis() - RingPolicy.FIRST_COOLDOWN, a.id());
        Res second = call("POST", "/rings/" + b.id(), a.token(), null);
        assertEquals(200, second.status());
        assertEquals(second.body().path("serverTime").asLong() + RingPolicy.NEXT_COOLDOWN, second.body().path("nextAllowedAt").asLong());

        db.update("UPDATE rings SET last_at=? WHERE caller_id=?", System.currentTimeMillis() - RingPolicy.FIRST_COOLDOWN, a.id());
        assertEquals(429, call("POST", "/rings/" + b.id(), a.token(), null).status());

        // An hour of quiet starts the ladder over.
        db.update("UPDATE rings SET last_at=? WHERE caller_id=?", System.currentTimeMillis() - RingPolicy.STREAK_RESET, a.id());
        Res fresh = call("POST", "/rings/" + b.id(), a.token(), null);
        assertEquals(fresh.body().path("serverTime").asLong() + RingPolicy.FIRST_COOLDOWN, fresh.body().path("nextAllowedAt").asLong());
    }

    @Test
    void blockStopsMessagesAndRings() throws Exception {
        boot(false, null);
        User a = user("alice"), b = user("bobby");
        call("POST", "/contacts", b.token(), Map.of("userId", a.id()));
        assertEquals(204, call("PUT", "/blocks/" + a.id(), b.token(), null).status());
        assertEquals(403, call("POST", "/messages", a.token(), Map.of("recipientId", b.id(), "clientId", UUID.randomUUID().toString(), "envelope", "x")).status());
        assertEquals(403, call("POST", "/rings/" + b.id(), a.token(), null).status());
        assertEquals(204, call("DELETE", "/blocks/" + a.id(), b.token(), null).status());
        sendMsg(a, b, "x");
    }

    @Test
    void passwordChangeRevokesOtherSessions() throws Exception {
        boot(false, null);
        User a = user("alice");
        int key = "alice".hashCode() & 0x7f;
        String second = call("POST", "/auth/login", null, Map.of("email", "alice@test.io", "authKey", b64(32, key))).body().path("token").asText();
        Map<String, Object> change = new HashMap<>();
        change.put("currentAuthKey", b64(32, 1));
        change.put("authKey", b64(32, 2));
        change.put("kdfSalt", b64(16, 2));
        change.put("kdfIterations", 600000);
        change.put("wrappedPrivateKey", b64(60, 2));
        assertEquals(401, call("POST", "/me/password", a.token(), change).status());
        change.put("currentAuthKey", b64(32, key));
        assertEquals(204, call("POST", "/me/password", a.token(), change).status());
        assertEquals(401, call("GET", "/me", second, null).status());
        assertEquals(200, call("GET", "/me", a.token(), null).status());
    }

    @Test
    void deleteAccountRemovesData() throws Exception {
        boot(false, null);
        User a = user("alice"), b = user("bobby");
        sendMsg(a, b, "x");
        assertEquals(401, call("POST", "/me/delete", a.token(), Map.of("authKey", b64(32, 3))).status());
        assertEquals(204, call("POST", "/me/delete", a.token(), Map.of("authKey", b64(32, "alice".hashCode() & 0x7f))).status());
        assertEquals(401, call("GET", "/me", a.token(), null).status());
        assertEquals(0, call("GET", "/sync", b.token(), null).body().path("messages").size());
        assertEquals(404, call("GET", "/users/by-nickname/alice", b.token(), null).status());
    }

    @Test
    void lookupIsExactAndHidesPrivateFields() throws Exception {
        boot(false, null);
        User a = user("alice");
        user("bobby");
        Res r = call("GET", "/users/by-nickname/BOBBY", a.token(), null);
        assertEquals(200, r.status());
        assertTrue(r.body().path("email").isMissingNode());
        assertTrue(r.body().path("wrappedPrivateKey").isMissingNode());
        assertEquals(404, call("GET", "/users/by-nickname/bob", a.token(), null).status());
        assertEquals(404, call("GET", "/users/by-nickname/%25", a.token(), null).status());
    }

    @Test
    void pushCarriesNoPlaintextAndRingUsesCustomSound() throws Exception {
        boot(false, null);
        User a = user("alice"), b = user("bobby");
        call("PUT", "/me/push-token", b.token(), Map.of("token", "ab".repeat(32), "sandbox", true));
        sendMsg(a, b, "cipher");
        assertEquals(1, pushes.size());
        assertEquals("cipher", pushes.get(0).payload().get("envelope"));
        call("POST", "/contacts", b.token(), Map.of("userId", a.id()));
        call("POST", "/rings/" + b.id(), a.token(), null);
        assertEquals(2, pushes.size());
        assertTrue(pushes.get(1).payload().get("aps").toString().contains("ring.caf"));
    }

    @Test
    void websocketRequiresTokenAndPokesOnMessage() throws Exception {
        boot(false, null);
        User a = user("alice"), b = user("bobby");

        var closed = new CompletableFuture<Integer>();
        http.newWebSocketBuilder().buildAsync(URI.create("ws://localhost:" + port + "/api/v1/ws"), new WebSocket.Listener() {
            @Override
            public void onOpen(WebSocket ws) {
                ws.sendText("{\"token\":\"nope\"}", true);
                ws.request(10);
            }

            @Override
            public CompletionStage<?> onClose(WebSocket ws, int code, String reason) {
                closed.complete(code);
                return null;
            }
        }).get(5, TimeUnit.SECONDS);
        assertEquals(4401, closed.get(5, TimeUnit.SECONDS));

        var ready = new CompletableFuture<Void>();
        var poked = new CompletableFuture<String>();
        http.newWebSocketBuilder().buildAsync(URI.create("ws://localhost:" + port + "/api/v1/ws"), new WebSocket.Listener() {
            @Override
            public void onOpen(WebSocket ws) {
                ws.sendText("{\"token\":\"" + b.token() + "\"}", true);
                ws.request(10);
            }

            @Override
            public CompletionStage<?> onText(WebSocket ws, CharSequence data, boolean last) {
                String s = data.toString();
                if (s.contains("ready")) ready.complete(null);
                else poked.complete(s);
                ws.request(1);
                return null;
            }
        }).get(5, TimeUnit.SECONDS);
        ready.get(5, TimeUnit.SECONDS);
        sendMsg(a, b, "secret-ciphertext");
        String event = poked.get(5, TimeUnit.SECONDS);
        assertTrue(event.contains("sync"));
        assertFalse(event.contains("secret-ciphertext"));

        assertNotEquals(a.id(), b.id());
    }
}
