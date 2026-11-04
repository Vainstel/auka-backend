package io.vainslab.auka;

/** Escalating cooldown: first ring is free, the next after 3 minutes, every later one after 10. */
final class RingPolicy {
    static final long FIRST_COOLDOWN = 3 * 60_000L;
    static final long NEXT_COOLDOWN = 10 * 60_000L;
    static final long STREAK_RESET = 60 * 60_000L;
    static final int RING_SECONDS = 20;

    private RingPolicy() {
    }

    /** Streak in force at {@code now}; an hour of quiet starts the ladder over. */
    static int effectiveStreak(int streak, long lastAt, long now) {
        return now - lastAt >= STREAK_RESET ? 0 : streak;
    }

    /** When the next ring becomes possible, given how many rings the current streak holds. */
    static long nextAllowedAt(int streak, long lastAt) {
        if (streak <= 0) return 0;
        return lastAt + (streak == 1 ? FIRST_COOLDOWN : NEXT_COOLDOWN);
    }
}
