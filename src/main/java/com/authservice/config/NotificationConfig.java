package com.authservice.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

/**
 * Default notification channel: logs emails/SMS to the console.
 * Any other NotificationService bean (SMTP, SMS provider) replaces this one.
 */
@Configuration(proxyBeanMethods = false)
public class NotificationConfig {

    private static final Logger log = LoggerFactory.getLogger(NotificationConfig.class);

    @Bean
    @ConditionalOnProperty(name = "app.mail.enabled", havingValue = "false", matchIfMissing = true)
    @ConditionalOnMissingBean(NotificationService.class)
    NotificationService devLogNotificationService() {
        return new NotificationService() {
            @Override
            public void sendEmail(String to, String subject, String body) {
                log.info("[DEV EMAIL] to={} subject={} body={}", to, subject, body);
            }

            @Override
            public void sendSms(String to, String body) {
                log.info("[DEV SMS] to={} body={}", to, body);
            }
        };
    }
}
