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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RelayIT {
    @TempDir
    Path dir;

    private final ObjectMapper json = Main.jsonMapper();
    private final HttpClient http = HttpClient.newHttpClient();
    private final List<String> delivered = Collections.synchronizedList(new ArrayList<>());
    private final List<Javalin> apps = new ArrayList<>();
    private Db db;

    @AfterEach
    void stop() {
        apps.forEach(Javalin::stop);
        if (db != null) db.close();
    }

    private static int freePort() throws Exception {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        }
    }

    private Pusher fakeApple() {
        return (token, sandbox, push) -> {
            if (token.equals("dead".repeat(8))) return 410;
            delivered.add(token + (sandbox ? ":sandbox" : ":prod") + ":" + push.payload().get("type"));
            return 200;
        };
    }

    private int startRelay(byte[] secret) throws Exception {
        int port = freePort();
        Map<String, String> env = Map.of("PORT", String.valueOf(port), "DATA_DIR", dir.toString());
        apps.add(Relay.start(Config.fromEnv(env), secret, json, fakeApple()));
        return port;
    }

    private record Res(int status, JsonNode body) {
    }

    private Res post(String url, String token, Object body) throws Exception {
        var b = HttpRequest.newBuilder(URI.create(url)).POST(HttpRequest.BodyPublishers.ofByteArray(json.writeValueAsBytes(body)));
        if (token != null) b.header("Authorization", "Bearer " + token);
        var r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        return new Res(r.statusCode(), r.body().isEmpty() ? json.nullNode() : json.readTree(r.body()));
    }

    private String handle(int relayPort, String token, boolean sandbox) throws Exception {
        Res r = post("http://localhost:" + relayPort + "/relay/v1/register", null, Map.of("token", token, "sandbox", sandbox));
        assertEquals(200, r.status(), r.body().toString());
        return r.body().path("handle").asText();
    }

    @Test
    void handlesWorkOnEveryRelayWithTheSameSecretAndCannotBeForged() throws Exception {
        byte[] secret = new byte[32];
        new java.util.Random(3).nextBytes(secret);
        int primary = startRelay(secret);
        int backup = startRelay(secret);
        String token = "ab".repeat(32);
        String handle = handle(primary, token, true);
        assertFalse(handle.contains(token), "the handle must not reveal the device token");
        assertNotEquals(handle, handle(primary, token, true));

        String sender = UUID.randomUUID().toString();
        Map<String, Object> wake = new HashMap<>(Map.of("handle", handle, "kind", "message", "senderId", sender, "messageId", 5, "badge", 1));
        assertEquals(202, post("http://localhost:" + backup + "/relay/v1/push", null, wake).status());
        assertEquals(List.of(token + ":sandbox:message"), delivered);

        // Any change to the handle, or a handle made with another secret, is refused.
        wake.put("handle", handle.substring(0, handle.length() - 2) + (handle.endsWith("A") ? "BB" : "AA"));
        assertEquals(400, post("http://localhost:" + primary + "/relay/v1/push", null, wake).status());
        int foreign = startRelay(new byte[32]);
        wake.put("handle", handle(foreign, token, false));
        assertEquals(400, post("http://localhost:" + primary + "/relay/v1/push", null, wake).status());

        // Nothing but known kinds and well-formed ids gets through to a phone.
        wake.put("handle", handle);
        wake.put("kind", "anything");
        assertEquals(400, post("http://localhost:" + primary + "/relay/v1/push", null, wake).status());
        wake.put("kind", "ring");
        wake.put("ringId", "not-a-uuid");
        assertEquals(400, post("http://localhost:" + primary + "/relay/v1/push", null, wake).status());

        String dead = handle(primary, "dead".repeat(8), false);
        assertEquals(410, post("http://localhost:" + primary + "/relay/v1/push", null,
                Map.of("handle", dead, "kind", "ring", "senderId", sender, "ringId", UUID.randomUUID().toString())).status());
    }

    @Test
    void serverFallsBackToTheSecondRelayAndPushesThroughHandles() throws Exception {
        byte[] secret = Base64.getDecoder().decode(Base64.getEncoder().encodeToString(new byte[32]));
        int relay = startRelay(secret);
        int deadPort = freePort();
        int port = freePort();
        Map<String, String> env = new HashMap<>();
        env.put("PORT", String.valueOf(port));
        env.put("DATA_DIR", dir.resolve("server").toString());
        env.put("PUSH_RELAYS", "http://localhost:" + deadPort + ",http://localhost:" + relay);
        db = new Db(dir.resolve("server"));
        apps.add(Main.start(Config.fromEnv(env), db, json, (to, code) -> {
        }, new Pusher.Noop()));
        String base = "http://localhost:" + port + "/api/v1";

        JsonNode info = json.readTree(http.send(HttpRequest.newBuilder(URI.create(base + "/server-info")).build(),
                HttpResponse.BodyHandlers.ofString()).body());
        assertEquals("relay", info.path("pushMode").asText());
        assertEquals(2, info.path("relays").size());

        String[] tokens = new String[2];
        String[] ids = new String[2];
        for (int i = 0; i < 2; i++) {
            Map<String, Object> reg = new HashMap<>();
            reg.put("email", "u" + i + "@test.io");
            reg.put("nickname", "user" + i);
            reg.put("displayName", "U" + i);
            reg.put("authKey", Base64.getEncoder().encodeToString(new byte[32]));
            reg.put("kdfSalt", Base64.getEncoder().encodeToString(new byte[16]));
            reg.put("kdfIterations", 600000);
            reg.put("publicKey", Base64.getEncoder().encodeToString(new byte[32]));
            reg.put("wrappedPrivateKey", Base64.getEncoder().encodeToString(new byte[60]));
            JsonNode r = post(base + "/auth/register", null, reg).body();
            tokens[i] = r.path("token").asText();
            ids[i] = r.path("user").path("id").asText();
        }
        String deviceToken = "cd".repeat(32);
        String handle = handle(relay, deviceToken, false);
        var put = HttpRequest.newBuilder(URI.create(base + "/me/push-token")).header("Authorization", "Bearer " + tokens[1])
                .PUT(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(Map.of("handle", handle)))).build();
        assertEquals(204, http.send(put, HttpResponse.BodyHandlers.discarding()).statusCode());

        assertEquals(200, post(base + "/messages", tokens[0],
                Map.of("recipientId", ids[1], "clientId", UUID.randomUUID().toString(), "envelope", "secret")).status());
        for (int i = 0; i < 50 && delivered.isEmpty(); i++) Thread.sleep(100);
        assertEquals(List.of(deviceToken + ":prod:message"), delivered);

        // The push extension fetches the message by id; outsiders can't.
        long messageId = post(base + "/messages", tokens[0],
                Map.of("recipientId", ids[1], "clientId", UUID.randomUUID().toString(), "envelope", "second")).body().path("id").asLong();
        var get = HttpRequest.newBuilder(URI.create(base + "/messages/" + messageId)).header("Authorization", "Bearer " + tokens[1]).build();
        assertTrue(http.send(get, HttpResponse.BodyHandlers.ofString()).body().contains("second"));
    }
}
