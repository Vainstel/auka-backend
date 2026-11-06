package io.vainslab.auka;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

/** Encrypted blobs on disk, one file per id. The server never sees what is inside. */
final class FileStore {
    private static final String PART = ".part";
    private final Path dir;

    FileStore(Path dir) {
        this.dir = dir;
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot create " + dir, e);
        }
    }

    /** Streams to disk without holding the file in memory; returns -1 once more than {@code max} bytes arrive. */
    long write(String id, InputStream in, long max) throws IOException {
        Path part = dir.resolve(id + PART);
        long total = 0;
        boolean tooLarge = false;
        try (in; OutputStream out = Files.newOutputStream(part)) {
            byte[] buffer = new byte[64 * 1024];
            int n;
            while ((n = in.read(buffer)) > 0) {
                total += n;
                if (total > max) {
                    tooLarge = true;
                    break;
                }
                out.write(buffer, 0, n);
            }
        } catch (IOException e) {
            Files.deleteIfExists(part);
            throw e;
        }
        if (tooLarge) {
            Files.deleteIfExists(part);
            return -1;
        }
        Files.move(part, dir.resolve(id), StandardCopyOption.ATOMIC_MOVE);
        return total;
    }

    InputStream open(String id) throws IOException {
        return Files.newInputStream(dir.resolve(id));
    }

    void delete(String id) {
        try {
            Files.deleteIfExists(dir.resolve(id));
            Files.deleteIfExists(dir.resolve(id + PART));
        } catch (IOException ignored) {
        }
    }

    /** Finished blobs, plus uploads that were abandoned more than an hour ago. */
    List<String> storedIds() {
        List<String> out = new ArrayList<>();
        long staleBefore = System.currentTimeMillis() - 60 * 60_000L;
        try (var stream = Files.list(dir)) {
            for (Path p : stream.toList()) {
                String name = p.getFileName().toString();
                if (!name.endsWith(PART)) {
                    out.add(name);
                } else if (Files.getLastModifiedTime(p).toMillis() < staleBefore) {
                    Files.deleteIfExists(p);
                }
            }
        } catch (IOException ignored) {
        }
        return out;
    }
}
