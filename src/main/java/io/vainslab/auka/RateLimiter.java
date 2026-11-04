package io.vainslab.auka;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory fixed-window counters: one process, so nothing needs sharing. */
final class RateLimiter {
    private record Window(long startedAt, int count) {
    }

    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    /** Throws 429 once {@code key} has been used more than {@code limit} times in the window. */
    void check(String key, int limit, long windowMillis) {
        long now = System.currentTimeMillis();
        Window w = windows.compute(key, (k, old) ->
                old == null || now - old.startedAt() >= windowMillis
                        ? new Window(now, 1)
                        : new Window(old.startedAt(), old.count() + 1));
        if (w.count() > limit) {
            long retryAfter = Math.max(1, (w.startedAt() + windowMillis - now) / 1000);
            throw new ApiError(429, "rate_limited", Map.of("retryAfterSeconds", retryAfter));
        }
    }

    /** For counting only failures: test first, record only after something actually failed. */
    boolean isOver(String key, int limit, long windowMillis) {
        Window w = windows.get(key);
        return w != null && System.currentTimeMillis() - w.startedAt() < windowMillis && w.count() >= limit;
    }

    void hit(String key, long windowMillis) {
        long now = System.currentTimeMillis();
        windows.compute(key, (k, old) ->
                old == null || now - old.startedAt() >= windowMillis
                        ? new Window(now, 1)
                        : new Window(old.startedAt(), old.count() + 1));
    }

    void prune(long maxAgeMillis) {
        long now = System.currentTimeMillis();
        windows.values().removeIf(w -> now - w.startedAt() > maxAgeMillis);
    }
}
