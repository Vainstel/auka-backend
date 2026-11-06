package io.vainslab.auka;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Sends wake-ups through the push relays in order; the next one takes over when one is down. */
final class RelayClient {
    private static final Logger log = LoggerFactory.getLogger(RelayClient.class);

    /** A relay URL, optionally pinned to its self-signed certificate: "https://1.2.3.4:8444|AB:CD:...". */
    record Target(String url, String pin) {
        static Target parse(String spec) {
            String[] parts = spec.trim().split("\\|", 2);
            String url = parts[0].replaceAll("/+$", "");
            String pin = parts.length > 1 ? parts[1].trim().toUpperCase() : null;
            if (!url.startsWith("https://") && !url.startsWith("http://")) throw new IllegalStateException("Bad relay URL: " + url);
            return new Target(url, pin == null || pin.isEmpty() ? null : pin);
        }

        Map<String, Object> describe() {
            return pin == null ? Map.of("url", url) : Map.of("url", url, "pin", pin);
        }
    }

    enum Result {
        DELIVERED, GONE, FAILED
    }

    private final List<Target> targets;
    private final List<HttpClient> clients = new ArrayList<>();
    private final ObjectMapper json;

    RelayClient(List<Target> targets, ObjectMapper json) {
        this.targets = targets;
        this.json = json;
        for (int i = 0; i < targets.size(); i++) clients.add(client(targets.get(i), timeout(i)));
    }

    static List<Target> parseAll(String specs) {
        List<Target> out = new ArrayList<>();
        if (specs == null || specs.isBlank() || specs.trim().equalsIgnoreCase("none")) return out;
        for (String spec : specs.split(",")) if (!spec.isBlank()) out.add(Target.parse(spec));
        return out;
    }

    List<Target> targets() {
        return targets;
    }

    boolean enabled() {
        return !targets.isEmpty();
    }

    Result send(Map<String, Object> body) {
        byte[] bytes;
        try {
            bytes = json.writeValueAsBytes(body);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        for (int i = 0; i < targets.size(); i++) {
            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(targets.get(i).url() + Relay.PREFIX + "/push"))
                        .timeout(timeout(i))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(bytes))
                        .build();
                int status = clients.get(i).send(req, HttpResponse.BodyHandlers.discarding()).statusCode();
                if (status == 202 || status == 200) return Result.DELIVERED;
                if (status == 410) return Result.GONE;
                // A rejected handle stays rejected on every relay; only outages are worth retrying elsewhere.
                if (status >= 400 && status < 500) return Result.FAILED;
                log.warn("Relay {} answered {}", targets.get(i).url(), status);
            } catch (Exception e) {
                log.warn("Relay {} unreachable: {}", targets.get(i).url(), e.getClass().getSimpleName());
            }
        }
        return Result.FAILED;
    }

    /** With a pin, exactly that certificate is accepted; without one, the system's trusted CAs. */
    /** The primary gets 5 s, so a blocked one (Cloudflare in some countries) delays a push only briefly; backups get 15 s. */
    static Duration timeout(int index) {
        return Duration.ofSeconds(index == 0 ? 5 : 15);
    }

    private static HttpClient client(Target t, Duration timeout) {
        var builder = HttpClient.newBuilder().connectTimeout(timeout);
        if (t.pin() != null) {
            try {
                SSLContext ssl = SSLContext.getInstance("TLS");
                ssl.init(null, new TrustManager[]{new PinnedTrust(t.pin())}, null);
                builder.sslContext(ssl);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
        return builder.build();
    }

    private record PinnedTrust(String pin) implements X509TrustManager {
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            try {
                String actual = HexFormat.ofDelimiter(":").withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded()));
                if (!actual.equals(pin)) throw new java.security.cert.CertificateException("Relay certificate does not match the pin");
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new java.security.cert.CertificateException(e);
            }
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            throw new UnsupportedOperationException();
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
