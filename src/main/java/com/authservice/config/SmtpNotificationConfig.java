package com.authservice.config;

import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

@Configuration(proxyBeanMethods = false)
public class SmtpNotificationConfig {

    private static final Logger log = LoggerFactory.getLogger(SmtpNotificationConfig.class);

    @Bean
    @ConditionalOnProperty(name = "app.mail.enabled", havingValue = "true")
    NotificationService smtpNotificationService(
            JavaMailSender mailSender,
            @Value("${app.mail.from}") String from) {
        return new NotificationService() {
            @Override
            public void sendEmail(String to, String subject, String body) {
                try {
                    MimeMessage message = mailSender.createMimeMessage();
                    MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
                    helper.setFrom(from);
                    helper.setTo(to);
                    helper.setSubject(subject);
                    helper.setText(body, true);
                    mailSender.send(message);
                    log.info("Email sent to {} subject={}", to, subject);
                } catch (Exception e) {
                    log.error("Failed to send email to {} subject={}", to, subject, e);
                    throw new IllegalStateException("Email delivery failed", e);
                }
            }

            @Override
            public void sendSms(String to, String body) {
                log.warn("SMS provider not configured; sms to={} dropped", to);
            }
        };
    }
}
