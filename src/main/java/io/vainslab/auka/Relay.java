package io.vainslab.auka;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Push relay: one shared service holding the Apple key, so self-hosted servers can wake the official app.
 * Stateless: a handle is the device token encrypted with RELAY_SECRET, so every relay sharing the secret accepts it.
 * It never receives message content, only "wake this handle for a message or a ring".
 */
final class Relay {
    private static final Logger log = LoggerFactory.getLogger(Relay.class);
    static final String PREFIX = "/relay/v1";
    private static final Pattern APNS_TOKEN = Pattern.compile("^[0-9a-fA-F]{32,256}$");
    private static final long MINUTE = 60_000L;
    private static final long HOUR = 60 * MINUTE;

    private record Device(String token, boolean sandbox) {
    }

    private final SecretKeySpec key;
    private final ObjectMapper json;
    private final Pusher pusher;
    private final boolean criticalRing;
    private final RateLimiter limiter = new RateLimiter();

    Relay(byte[] secret, ObjectMapper json, Pusher pusher, boolean criticalRing) {
        if (secret.length != 32) throw new IllegalStateException("RELAY_SECRET must be 32 bytes in base64");
        this.key = new SecretKeySpec(secret, "AES");
        this.json = json;
        this.pusher = pusher;
        this.criticalRing = criticalRing;
    }

    static Javalin start(Config config, byte[] secret, ObjectMapper json, Pusher pusher) {
        Relay relay = new Relay(secret, json, pusher, config.apnsCriticalRing());
        Javalin app = Javalin.create(c -> {
            c.startup.showJavalinBanner = false;
            c.http.maxRequestSize = 4096;
            c.concurrency.useVirtualThreads = true;
            c.jetty.port = config.port();
            c.jetty.modifyHttpConfiguration(http -> http.setSendServerVersion(false));
            if (config.tlsKeystore() != null) c.jetty.addConnector((server, http) -> Main.tlsConnector(server, http, config));
            c.routes.exception(ApiError.class, (e, ctx) -> {
                Map<String, Object> out = new HashMap<>(e.extra);
                out.put("error", e.code);
                ctx.status(e.status).contentType("application/json").result(write(json, out));
            });
            c.routes.exception(Exception.class, (e, ctx) -> {
                log.error("Unhandled {}", e.getClass().getSimpleName(), e);
                ctx.status(500).contentType("application/json").result("{\"error\":\"internal\"}");
            });
            c.routes.get(PREFIX + "/info", ctx -> ctx.contentType("application/json").result("{\"service\":\"auka-relay\",\"version\":1}"));
            c.routes.post(PREFIX + "/register", relay::register);
            c.routes.post(PREFIX + "/push", relay::push);
            c.routes.before(ctx -> relay.limiter.check("ip:" + ctx.req().getRemoteAddr(), 1200, MINUTE));
        });
        app.start();
        Thread.ofPlatform().daemon().start(() -> {
            while (true) {
                try {
                    Thread.sleep(HOUR);
                } catch (InterruptedException e) {
                    return;
                }
                relay.limiter.prune(2 * HOUR);
            }
        });
        return app;
    }

    /** Called by the app itself, so the device token never passes through anyone's self-hosted server. */
    private void register(Context ctx) {
        limiter.check("ip:register:" + ctx.req().getRemoteAddr(), 30, HOUR);
        JsonNode b = body(ctx);
        String token = b.path("token").asText("");
        if (!APNS_TOKEN.matcher(token).matches()) throw new ApiError(400, "invalid_request");
        String handle = seal(new Device(token.toLowerCase(), b.path("sandbox").asBoolean(false)));
        ctx.contentType("application/json").result(write(json, Map.of("handle", handle)));
    }

    /** Called by servers. Only handles this relay issued work, and every field is checked so nothing arbitrary reaches a phone. */
    private void push(Context ctx) {
        JsonNode b = body(ctx);
        String handle = b.path("handle").asText("");
        Device device = open(handle).orElseThrow(() -> new ApiError(400, "invalid_handle"));
        String kind = b.path("kind").asText("");
        String senderId = uuidOrNull(b.path("senderId").asText(null));
        Map<String, Object> payload;
        String collapseId = null;
        if (kind.equals("message")) {
            limiter.check("handle:msg:" + handle, 120, MINUTE);
            long messageId = b.path("messageId").asLong(0);
            if (messageId <= 0 || senderId == null) throw new ApiError(400, "invalid_request");
            int badge = Math.max(0, Math.min(9999, b.path("badge").asInt(0)));
            payload = messagePayload(senderId, messageId, badge);
            collapseId = "m" + messageId;
        } else if (kind.equals("ring")) {
            limiter.check("handle:ring:" + handle, 10, HOUR);
            String ringId = uuidOrNull(b.path("ringId").asText(null));
            if (ringId == null || senderId == null) throw new ApiError(400, "invalid_request");
            payload = ringPayload(senderId, ringId, criticalRing);
        } else {
            throw new ApiError(400, "invalid_request");
        }
        int status = pusher.deliver(device.token(), device.sandbox(), new Pusher.Push(payload, collapseId));
        if (status == 410) throw new ApiError(410, "handle_gone");
        if (status != 200) throw new ApiError(502, "push_failed");
        ctx.status(202);
    }

    // --- payloads, shared with direct APNs on the main server ---

    /** No text at all: the app's extension fetches and decrypts the message itself. */
    static Map<String, Object> messagePayload(String senderId, long messageId, int badge) {
        Map<String, Object> aps = new HashMap<>();
        aps.put("alert", Map.of("title", "Auka", "loc-key", "PUSH_MESSAGE"));
        aps.put("sound", "default");
        aps.put("badge", badge);
        aps.put("mutable-content", 1);
        aps.put("thread-id", senderId);
        Map<String, Object> payload = new HashMap<>();
        payload.put("aps", aps);
        payload.put("type", "message");
        payload.put("senderId", senderId);
        payload.put("messageId", messageId);
        return payload;
    }

    static Map<String, Object> ringPayload(String senderId, String ringId, boolean critical) {
        Map<String, Object> aps = new HashMap<>();
        aps.put("alert", Map.of("title", "Auka", "loc-key", "PUSH_RING"));
        if (critical) {
            aps.put("sound", Map.of("critical", 1, "name", "ring.caf", "volume", 1.0));
            aps.put("interruption-level", "critical");
        } else {
            aps.put("sound", "ring.caf");
            aps.put("interruption-level", "time-sensitive");
        }
        aps.put("relevance-score", 1.0);
        aps.put("mutable-content", 1);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("aps", aps);
        payload.put("type", "ring");
        payload.put("ringId", ringId);
        payload.put("senderId", senderId);
        return payload;
    }

    // --- handles ---

    String seal(Device device) {
        try {
            byte[] nonce = Secrets.randomBytes(12);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            c.updateAAD("auka-relay-v1".getBytes(StandardCharsets.UTF_8));
            byte[] ct = c.doFinal(((device.sandbox() ? "s" : "p") + device.token()).getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(ByteBuffer.allocate(12 + ct.length).put(nonce).put(ct).array());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private java.util.Optional<Device> open(String handle) {
        try {
            if (handle.isEmpty() || handle.length() > 400) return java.util.Optional.empty();
            byte[] raw = Base64.getUrlDecoder().decode(handle);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, raw, 0, 12));
            c.updateAAD("auka-relay-v1".getBytes(StandardCharsets.UTF_8));
            String plain = new String(c.doFinal(raw, 12, raw.length - 12), StandardCharsets.UTF_8);
            return java.util.Optional.of(new Device(plain.substring(1), plain.charAt(0) == 's'));
        } catch (Exception e) {
            return java.util.Optional.empty();
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

    private static String uuidOrNull(String raw) {
        try {
            return raw == null ? null : UUID.fromString(raw).toString();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String write(ObjectMapper json, Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
