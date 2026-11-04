package io.vainslab.auka;

import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

interface Mailer {
    void sendCode(String to, String code);

    final class Smtp implements Mailer {
        private static final Logger log = LoggerFactory.getLogger(Mailer.class);

        private final Session session;
        private final Config config;

        Smtp(Config config) {
            this.config = config;
            Properties p = new Properties();
            p.put("mail.smtp.host", config.smtpHost());
            p.put("mail.smtp.port", String.valueOf(config.smtpPort()));
            p.put("mail.smtp.auth", String.valueOf(config.smtpUsername() != null));
            p.put("mail.smtp.starttls.enable", "true");
            p.put("mail.smtp.starttls.required", "true");
            p.put("mail.smtp.ssl.checkserveridentity", "true");
            p.put("mail.smtp.connectiontimeout", "10000");
            p.put("mail.smtp.timeout", "15000");
            p.put("mail.smtp.writetimeout", "15000");
            session = Session.getInstance(p, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(config.smtpUsername(), config.smtpPassword());
                }
            });
        }

        @Override
        public void sendCode(String to, String code) {
            // Off the request thread, so response timing does not reveal whether an account exists.
            Thread.startVirtualThread(() -> {
                try {
                    MimeMessage m = new MimeMessage(session);
                    m.setFrom(new InternetAddress(config.mailFrom(), config.mailFromName(), "UTF-8"));
                    m.setRecipient(Message.RecipientType.TO, new InternetAddress(to, true));
                    m.setSubject(code + " — код подтверждения / verification code", "UTF-8");
                    m.setText("Код подтверждения: " + code + "\nVerification code: " + code
                            + "\n\nДействует 10 минут. Valid for 10 minutes.\n"
                            + "Если это были не вы, просто проигнорируйте письмо.\n", "UTF-8");
                    Transport.send(m);
                } catch (Exception e) {
                    log.warn("Mail send failed: {}", e.getClass().getSimpleName());
                }
            });
        }
    }
}
