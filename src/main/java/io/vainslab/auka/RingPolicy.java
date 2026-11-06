package io.vainslab.auka;

/** Escalating cooldown: the first ring is free, then 1, 3, 5 and from there on 10 minutes between rings. */
final class RingPolicy {
    private static final long MINUTE = 60_000L;
    private static final long[] COOLDOWNS = {MINUTE, 3 * MINUTE, 5 * MINUTE, 10 * MINUTE};
    static final long STREAK_RESET = 60 * MINUTE;
    static final int RING_SECONDS = 20;

    private RingPolicy() {
    }

    /** Wait after the n-th ring of a streak (1-based). */
    static long cooldown(int streak) {
        return COOLDOWNS[Math.min(streak, COOLDOWNS.length) - 1];
    }

    /** Streak in force at {@code now}; an hour of quiet starts the ladder over. */
    static int effectiveStreak(int streak, long lastAt, long now) {
        return now - lastAt >= STREAK_RESET ? 0 : streak;
    }

    /** When the next ring becomes possible, given how many rings the current streak holds. */
    static long nextAllowedAt(int streak, long lastAt) {
        return streak <= 0 ? 0 : lastAt + cooldown(streak);
    }
}
