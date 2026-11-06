package io.vainslab.auka;

import java.nio.file.Path;
import java.util.Map;

/** All settings come from the environment; nothing secret lives in the repository. */
record Config(
        int port,
        Path dataDir,
        String tlsKeystore,
        String tlsKeystorePassword,
        String serverName,
        boolean trustProxy,
        String inviteCode,
        String smtpHost,
        int smtpPort,
        String smtpUsername,
        String smtpPassword,
        String mailFrom,
        String mailFromName,
        int mailMaxPerDay,
        String apnsKeyBase64,
        String apnsKeyId,
        String apnsTeamId,
        String apnsTopic,
        boolean apnsCriticalRing,
        int messageRetentionDays,
        long fileStorageMb,
        int fileTtlHours,
        int fileMaxMb
) {
    static Config fromEnv(Map<String, String> env) {
        String serverName = env.getOrDefault("SERVER_NAME", "Auka");
        return new Config(
                Integer.parseInt(env.getOrDefault("PORT", "8443")),
                Path.of(env.getOrDefault("DATA_DIR", "./data")),
                blankToNull(env.get("TLS_KEYSTORE")),
                env.getOrDefault("TLS_KEYSTORE_PASSWORD", ""),
                serverName,
                Boolean.parseBoolean(env.getOrDefault("TRUST_PROXY", "false")),
                blankToNull(env.get("INVITE_CODE")),
                blankToNull(env.get("SMTP_HOST")),
                Integer.parseInt(env.getOrDefault("SMTP_PORT", "587")),
                blankToNull(env.get("SMTP_USERNAME")),
                blankToNull(env.get("SMTP_PASSWORD")),
                env.getOrDefault("MAIL_FROM", ""),
                env.getOrDefault("MAIL_FROM_NAME", serverName),
                Integer.parseInt(env.getOrDefault("MAIL_MAX_PER_DAY", "200")),
                blankToNull(env.get("APNS_KEY_BASE64")),
                blankToNull(env.get("APNS_KEY_ID")),
                blankToNull(env.get("APNS_TEAM_ID")),
                blankToNull(env.get("APNS_TOPIC")),
                Boolean.parseBoolean(env.getOrDefault("APNS_CRITICAL_RING", "false")),
                Integer.parseInt(env.getOrDefault("MESSAGE_RETENTION_DAYS", "0")),
                Long.parseLong(env.getOrDefault("FILE_STORAGE_MB", "500")),
                Integer.parseInt(env.getOrDefault("FILE_TTL_HOURS", "168")),
                Integer.parseInt(env.getOrDefault("FILE_MAX_MB", "15"))
        );
    }

    /** With no SMTP configured the server runs single-factor: login and password only. */
    boolean emailVerification() {
        return smtpHost != null;
    }

    long fileStorageBytes() {
        return fileStorageMb * 1024 * 1024;
    }

    long fileMaxBytes() {
        return fileMaxMb * 1024L * 1024;
    }

    boolean apnsEnabled() {
        return apnsKeyBase64 != null && apnsKeyId != null && apnsTeamId != null && apnsTopic != null;
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s;
    }
}
