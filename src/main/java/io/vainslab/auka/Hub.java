package io.vainslab.auka;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.websocket.WsContext;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

/** Live sockets per user. Messages never travel here: a socket only gets "go and sync" pokes and rings. */
final class Hub {
    private record Client(WsContext ctx, String tokenHash) {
    }

    private final Map<String, Set<Client>> clients = new ConcurrentHashMap<>();
    private final ObjectMapper json;

    Hub(ObjectMapper json) {
        this.json = json;
    }

    void add(String userId, String tokenHash, WsContext ctx) {
        clients.computeIfAbsent(userId, k -> ConcurrentHashMap.newKeySet()).add(new Client(ctx, tokenHash));
    }

    void remove(String userId, WsContext ctx) {
        Set<Client> set = clients.get(userId);
        if (set != null) set.removeIf(c -> c.ctx().sessionId().equals(ctx.sessionId()));
    }

    void poke(String userId) {
        send(userId, Map.of("type", "sync"));
    }

    void send(String userId, Map<String, ?> event) {
        Set<Client> set = clients.get(userId);
        if (set == null || set.isEmpty()) return;
        String text;
        try {
            text = json.writeValueAsString(event);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
        for (Client c : set) {
            try {
                c.ctx().send(text);
            } catch (Exception ignored) {
                set.remove(c);
            }
        }
    }

    /** Revoked sessions must lose their live socket too, not just their token. */
    void closeSession(String userId, String tokenHash) {
        closeWhere(userId, c -> c.tokenHash().equals(tokenHash));
    }

    void closeOthers(String userId, String keepTokenHash) {
        closeWhere(userId, c -> !c.tokenHash().equals(keepTokenHash));
    }

    void closeAll(String userId) {
        closeWhere(userId, c -> true);
    }

    private void closeWhere(String userId, Predicate<Client> test) {
        Set<Client> set = clients.get(userId);
        if (set == null) return;
        for (Client c : set) {
            if (test.test(c)) {
                set.remove(c);
                try {
                    c.ctx().closeSession(4401, "session_revoked");
                } catch (Exception ignored) {
                }
            }
        }
    }
}
