package io.vainslab.auka;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLEncoder;
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

/** Android wake-ups through Firebase Cloud Messaging. Only data messages: ids, never content; the app fetches and decrypts itself. */
interface Fcm {
    /** Blocks until FCM answers; returns the HTTP status, 410 meaning the token is dead. */
    int deliver(String token, Map<String, String> data, boolean urgent);

    /** FCM HTTP v1 with a service-account OAuth token, on the JDK client: no Google SDK for one POST. */
    final class Http implements Fcm {
        private static final Logger log = LoggerFactory.getLogger(Fcm.class);
        private static final String SCOPE = "https://www.googleapis.com/auth/firebase.messaging";

        private final ObjectMapper json;
        private final String projectId;
        private final String clientEmail;
        private final String tokenUri;
        private final PrivateKey key;
        private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        private String accessToken;
        private long accessTokenUntil;

        Http(String serviceAccountBase64, ObjectMapper json) {
            this.json = json;
            try {
                JsonNode sa = json.readTree(Base64.getMimeDecoder().decode(serviceAccountBase64.trim()));
                projectId = sa.path("project_id").asText();
                clientEmail = sa.path("client_email").asText();
                tokenUri = sa.path("token_uri").asText("https://oauth2.googleapis.com/token");
                String body = sa.path("private_key").asText().replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
                key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
                if (projectId.isEmpty() || clientEmail.isEmpty()) throw new IllegalStateException("missing fields");
            } catch (Exception e) {
                throw new IllegalStateException("FCM_SERVICE_ACCOUNT_BASE64 is not a base64-encoded service account JSON", e);
            }
        }

        private synchronized String accessToken() throws Exception {
            long now = System.currentTimeMillis();
            if (accessToken != null && now < accessTokenUntil) return accessToken;
            var enc = Base64.getUrlEncoder().withoutPadding();
            String header = enc.encodeToString(json.writeValueAsBytes(Map.of("alg", "RS256", "typ", "JWT")));
            String claims = enc.encodeToString(json.writeValueAsBytes(Map.of(
                    "iss", clientEmail, "scope", SCOPE, "aud", tokenUri, "iat", now / 1000, "exp", now / 1000 + 3600)));
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(key);
            s.update((header + "." + claims).getBytes(StandardCharsets.US_ASCII));
            String jwt = header + "." + claims + "." + enc.encodeToString(s.sign());
            String form = "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", StandardCharsets.UTF_8) + "&assertion=" + jwt;
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(tokenUri)).timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) throw new IllegalStateException("Google token endpoint answered " + r.statusCode());
            JsonNode body = json.readTree(r.body());
            accessToken = body.path("access_token").asText();
            // Refresh well before Google's expiry so a push never goes out with a stale token.
            accessTokenUntil = now + Math.max(60, body.path("expires_in").asLong(3600) - 300) * 1000;
            return accessToken;
        }

        @Override
        public int deliver(String token, Map<String, String> data, boolean urgent) {
            try {
                Map<String, Object> android = Map.of("priority", "high", "ttl", urgent ? "60s" : "86400s");
                Map<String, Object> message = Map.of("message", Map.of("token", token, "data", data, "android", android));
                HttpRequest req = HttpRequest.newBuilder(URI.create("https://fcm.googleapis.com/v1/projects/" + projectId + "/messages:send"))
                        .timeout(Duration.ofSeconds(15))
                        .header("Authorization", "Bearer " + accessToken())
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(json.writeValueAsBytes(message)))
                        .build();
                HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (r.statusCode() == 200) return 200;
                // UNREGISTERED (404) is the only answer that means the app is gone; everything else may be ours or transient.
                if (r.statusCode() == 404 || r.body().contains("UNREGISTERED")) return 410;
                log.warn("FCM answered {}", r.statusCode());
                return r.statusCode();
            } catch (Exception e) {
                log.warn("FCM unreachable: {}", e.getClass().getSimpleName());
                return 0;
            }
        }
    }
}
