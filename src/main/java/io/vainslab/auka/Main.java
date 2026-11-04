package io.vainslab.auka;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.NetworkConnectionLimit;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class Main {
    private static final Logger log = LoggerFactory.getLogger(Main.class);
    private static final long MAX_BODY = 256 * 1024;
    private static final int MAX_CONNECTIONS = 256;

    public static void main(String[] args) {
        Config config = Config.fromEnv(System.getenv());
        if (config.inviteCode() == null && !Boolean.parseBoolean(System.getenv("ALLOW_OPEN_REGISTRATION"))) {
            log.error("Set INVITE_CODE, or ALLOW_OPEN_REGISTRATION=true to let anyone who finds this server register");
            System.exit(1);
        }
        ObjectMapper json = jsonMapper();
        Mailer mailer = config.emailVerification() ? new Mailer.Smtp(config) : (to, code) -> {
        };
        Pusher pusher = config.apnsEnabled() ? new Pusher.Apns(config, json) : new Pusher.Noop();
        start(config, new Db(config.dataDir()), json, mailer, pusher);
        log.info("Started on port {}: tls={}, emailVerification={}, push={}, inviteRequired={}",
                config.port(), config.tlsKeystore() != null, config.emailVerification(), config.apnsEnabled(), config.inviteCode() != null);
    }

    static ObjectMapper jsonMapper() {
        return new ObjectMapper().configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);
    }

    static Javalin start(Config config, Db db, ObjectMapper json, Mailer mailer, Pusher pusher) {
        Hub hub = new Hub(json);
        Api api = new Api(config, db, json, hub, mailer, pusher, new RateLimiter());
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "scheduler");
            t.setDaemon(true);
            return t;
        });

        Javalin app = Javalin.create(c -> {
            c.startup.showJavalinBanner = false;
            c.http.maxRequestSize = MAX_BODY;
            c.concurrency.useVirtualThreads = true;
            c.jetty.port = config.port();
            c.jetty.modifyHttpConfiguration(http -> {
                http.setSendServerVersion(false);
                http.setSendDateHeader(false);
            });
            if (config.tlsKeystore() != null) {
                c.jetty.addConnector((server, http) -> tlsConnector(server, http, config));
            }
            c.jetty.modifyServer(server -> server.addBean(new NetworkConnectionLimit(MAX_CONNECTIONS, server)));
            c.jetty.modifyWebSocketServletFactory(ws -> {
                ws.setMaxTextMessageSize(4096);
                ws.setIdleTimeout(Duration.ofMinutes(2));
            });

            c.routes.exception(ApiError.class, (e, ctx) -> {
                Map<String, Object> out = new java.util.HashMap<>(e.extra);
                out.put("error", e.code);
                ctx.status(e.status).contentType("application/json").result(writeJson(json, out));
            });
            c.routes.exception(Exception.class, (e, ctx) -> {
                log.error("Unhandled {} on {}", e.getClass().getSimpleName(), ctx.path(), e);
                ctx.status(500).contentType("application/json").result("{\"error\":\"internal\"}");
            });
            c.routes.error(404, ctx -> {
                if (ctx.result() == null) ctx.contentType("application/json").result("{\"error\":\"not_found\"}");
            });

            api.register(c);

            c.routes.wsBeforeUpgrade(Api.PREFIX + "/ws", api::checkWsUpgrade);
            c.routes.ws(Api.PREFIX + "/ws", ws -> {
                ws.onConnect(ctx -> {
                    ctx.enableAutomaticPings(30, TimeUnit.SECONDS);
                    // Whoever does not authenticate in time is dropped.
                    scheduler.schedule(() -> {
                        if (ctx.attribute("userId") == null && ctx.session.isOpen()) ctx.closeSession(4401, "auth_timeout");
                    }, 5, TimeUnit.SECONDS);
                });
                ws.onMessage(ctx -> {
                    if (ctx.attribute("userId") != null) return;
                    try {
                        JsonNode node = json.readTree(ctx.message());
                        Api.Session s = api.authenticateToken(node.path("token").asText(""));
                        ctx.attribute("userId", s.userId());
                        hub.add(s.userId(), s.tokenHash(), ctx);
                        ctx.send("{\"type\":\"ready\"}");
                    } catch (Exception e) {
                        ctx.closeSession(4401, "unauthorized");
                    }
                });
                ws.onClose(ctx -> {
                    String userId = ctx.attribute("userId");
                    if (userId != null) hub.remove(userId, ctx);
                });
            });
        });
        app.start();
        scheduler.scheduleAtFixedRate(() -> {
            try {
                api.cleanup();
            } catch (Exception e) {
                log.warn("Cleanup failed", e);
            }
        }, 1, 60, TimeUnit.MINUTES);
        return app;
    }

    private static String writeJson(ObjectMapper json, Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Serves HTTPS directly: an IP-only VPS gets a self-signed certificate that the app pins on first use. */
    private static ServerConnector tlsConnector(org.eclipse.jetty.server.Server server, HttpConfiguration http, Config config) {
        var ssl = new SslContextFactory.Server();
        ssl.setKeyStorePath(config.tlsKeystore());
        ssl.setKeyStorePassword(config.tlsKeystorePassword());
        ssl.setIncludeProtocols("TLSv1.3", "TLSv1.2");
        // Clients connect by bare IP, where SNI is absent and a host check would reject them.
        ssl.setSniRequired(false);
        var customizer = new SecureRequestCustomizer();
        customizer.setSniHostCheck(false);
        http.addCustomizer(customizer);
        var connector = new ServerConnector(server, ssl, new HttpConnectionFactory(http));
        connector.setPort(config.port());
        return connector;
    }
}
