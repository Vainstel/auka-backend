package io.vainslab.auka;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.function.Consumer;

interface Pusher {
    /** @param onDead called with the token when APNs says it no longer exists */
    void send(String token, boolean sandbox, Push push, Consumer<String> onDead);

    record Push(Map<String, Object> payload, String collapseId) {
    }

    final class Noop implements Pusher {
        @Override
        public void send(String token, boolean sandbox, Push push, Consumer<String> onDead) {
        }
    }

    /** Token-based APNs over the JDK HTTP/2 client: no extra dependency for one POST. */
    final class Apns implements Pusher {
        private static final Logger log = LoggerFactory.getLogger(Pusher.class);
        private static final long JWT_TTL = 50 * 60_000L;

        private final Config config;
        private final ObjectMapper json;
        private final PrivateKey key;
        private final HttpClient http = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        private String jwt;
        private long jwtAt;

        Apns(Config config, ObjectMapper json) {
            this.config = config;
            this.json = json;
            this.key = parseKey(config.apnsKeyBase64());
        }

        private static PrivateKey parseKey(String base64) {
            try {
                String pem = new String(Base64.getMimeDecoder().decode(base64), StandardCharsets.UTF_8);
                String body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
                return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
            } catch (Exception e) {
                throw new IllegalStateException("APNS_KEY_BASE64 is not a base64-encoded .p8 key", e);
            }
        }

        private synchronized String token() throws Exception {
            long now = System.currentTimeMillis();
            if (jwt == null || now - jwtAt > JWT_TTL) {
                var enc = Base64.getUrlEncoder().withoutPadding();
                String header = enc.encodeToString(json.writeValueAsBytes(Map.of("alg", "ES256", "kid", config.apnsKeyId())));
                String claims = enc.encodeToString(json.writeValueAsBytes(Map.of("iss", config.apnsTeamId(), "iat", now / 1000)));
                Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
                s.initSign(key);
                s.update((header + "." + claims).getBytes(StandardCharsets.US_ASCII));
                jwt = header + "." + claims + "." + enc.encodeToString(s.sign());
                jwtAt = now;
            }
            return jwt;
        }

        @Override
        public void send(String deviceToken, boolean sandbox, Push push, Consumer<String> onDead) {
            Thread.startVirtualThread(() -> {
                try {
                    String host = sandbox ? "api.sandbox.push.apple.com" : "api.push.apple.com";
                    HttpRequest.Builder req = HttpRequest.newBuilder(URI.create("https://" + host + "/3/device/" + deviceToken))
                            .timeout(Duration.ofSeconds(15))
                            .header("authorization", "bearer " + token())
                            .header("apns-topic", config.apnsTopic())
                            .header("apns-push-type", "alert")
                            .header("apns-priority", "10")
                            .POST(HttpRequest.BodyPublishers.ofByteArray(json.writeValueAsBytes(push.payload())));
                    if (push.collapseId() != null) req.header("apns-collapse-id", push.collapseId());
                    HttpResponse<String> res = http.send(req.build(), HttpResponse.BodyHandlers.ofString());
                    if (res.statusCode() == 410 || res.body().contains("BadDeviceToken")) {
                        onDead.accept(deviceToken);
                    } else if (res.statusCode() != 200) {
                        log.warn("APNs {}: {}", res.statusCode(), res.body());
                    }
                } catch (Exception e) {
                    log.warn("APNs send failed: {}", e.getClass().getSimpleName());
                }
            });
        }
    }
}
