package io.vainslab.auka;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/** One SQLite connection behind one lock: plenty for a family and keeps writes trivially serial. */
final class Db implements AutoCloseable {
    interface RowMapper<T> {
        T map(ResultSet rs) throws SQLException;
    }

    private static final String[] MIGRATIONS = {
            """
            CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);

            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                nickname TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                avatar_color INTEGER NOT NULL,
                auth_hash BLOB NOT NULL,
                auth_salt BLOB NOT NULL,
                kdf_salt TEXT NOT NULL,
                kdf_iterations INTEGER NOT NULL,
                public_key TEXT NOT NULL,
                wrapped_private_key TEXT NOT NULL,
                verified INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                device_name TEXT NOT NULL,
                apns_token TEXT,
                apns_sandbox INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL
            );
            CREATE INDEX sessions_user ON sessions(user_id);

            CREATE TABLE email_codes (
                email TEXT NOT NULL,
                purpose TEXT NOT NULL,
                code_hash BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (email, purpose)
            );

            CREATE TABLE code_failures (
                email TEXT NOT NULL,
                purpose TEXT NOT NULL,
                day INTEGER NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (email, purpose)
            );

            CREATE TABLE contacts (
                owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                contact_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (owner_id, contact_id)
            );

            CREATE TABLE blocks (
                owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                blocked_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (owner_id, blocked_id)
            );

            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seq INTEGER NOT NULL,
                sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                client_id TEXT NOT NULL,
                envelope TEXT,
                created_at INTEGER NOT NULL,
                deleted_at INTEGER,
                UNIQUE (sender_id, client_id)
            );
            CREATE INDEX messages_recipient_seq ON messages(recipient_id, seq);
            CREATE INDEX messages_sender_seq ON messages(sender_id, seq);

            CREATE TABLE read_markers (
                reader_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                peer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                up_to_id INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                PRIMARY KEY (reader_id, peer_id)
            );

            CREATE TABLE rings (
                caller_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                callee_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                last_at INTEGER NOT NULL,
                streak INTEGER NOT NULL,
                PRIMARY KEY (caller_id, callee_id)
            );
            """,
            """
            CREATE TABLE files (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                size INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX files_expires ON files(expires_at);
            ALTER TABLE messages ADD COLUMN file_id TEXT;
            """,
            """
            ALTER TABLE sessions ADD COLUMN push_handle TEXT;
            """
    };

    private final Connection conn;
    private final ReentrantLock lock = new ReentrantLock();

    Db(Path dataDir) {
        try {
            Files.createDirectories(dataDir);
            conn = DriverManager.getConnection("jdbc:sqlite:" + dataDir.resolve("auka.db"));
            try (Statement st = conn.createStatement()) {
                st.execute("PRAGMA journal_mode=WAL");
                st.execute("PRAGMA synchronous=NORMAL");
                st.execute("PRAGMA foreign_keys=ON");
                st.execute("PRAGMA secure_delete=ON");
                st.execute("PRAGMA cache_size=-4000");
            }
            migrate();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot open database", e);
        }
    }

    private void migrate() throws SQLException {
        int version;
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery("PRAGMA user_version")) {
            version = rs.getInt(1);
        }
        for (int v = version; v < MIGRATIONS.length; v++) {
            conn.setAutoCommit(false);
            try (Statement st = conn.createStatement()) {
                st.executeUpdate(MIGRATIONS[v]);
                st.execute("PRAGMA user_version=" + (v + 1));
                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        }
    }

    <T> T tx(Supplier<T> work) {
        lock.lock();
        try {
            if (!conn.getAutoCommit()) return work.get();
            conn.setAutoCommit(false);
            try {
                T result = work.get();
                conn.commit();
                return result;
            } catch (RuntimeException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        } finally {
            lock.unlock();
        }
    }

    int update(String sql, Object... args) {
        lock.lock();
        try (PreparedStatement ps = prepare(sql, args)) {
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        } finally {
            lock.unlock();
        }
    }

    <T> List<T> query(String sql, RowMapper<T> mapper, Object... args) {
        lock.lock();
        try (PreparedStatement ps = prepare(sql, args); ResultSet rs = ps.executeQuery()) {
            List<T> out = new ArrayList<>();
            while (rs.next()) out.add(mapper.map(rs));
            return out;
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        } finally {
            lock.unlock();
        }
    }

    <T> Optional<T> one(String sql, RowMapper<T> mapper, Object... args) {
        return query(sql, mapper, args).stream().findFirst();
    }

    boolean exists(String sql, Object... args) {
        return one(sql, rs -> true, args).orElse(false);
    }

    /** Stable random secret generated on first start; never leaves the data volume. */
    byte[] serverSecret() {
        return tx(() -> one("SELECT value FROM meta WHERE key='server_secret'", rs -> rs.getBytes(1)).orElseGet(() -> {
            byte[] secret = Secrets.randomBytes(32);
            update("INSERT INTO meta(key, value) VALUES ('server_secret', ?)", (Object) secret);
            return secret;
        }));
    }

    /** Every change a client must pick up takes the next value, so one cursor covers them all. */
    long nextSeq() {
        return tx(() -> {
            update("INSERT INTO meta(key, value) VALUES ('seq', 1) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1");
            return one("SELECT CAST(value AS INTEGER) FROM meta WHERE key='seq'", rs -> rs.getLong(1)).orElseThrow();
        });
    }

    private PreparedStatement prepare(String sql, Object... args) throws SQLException {
        PreparedStatement ps = conn.prepareStatement(sql);
        for (int i = 0; i < args.length; i++) ps.setObject(i + 1, args[i]);
        return ps;
    }

    @Override
    public void close() {
        try {
            conn.close();
        } catch (SQLException ignored) {
        }
    }
}
