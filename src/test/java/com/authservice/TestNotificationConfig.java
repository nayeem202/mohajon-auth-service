package com.authservice;

import com.authservice.config.NotificationService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@TestConfiguration
public class TestNotificationConfig {

    public static volatile String lastEmailCode;

    @Bean
    NotificationService testNotificationService() {
        return new NotificationService() {
            @Override
            public void sendEmail(String to, String subject, String body) {
                lastEmailCode = extractCode(body);
            }

            @Override
            public void sendSms(String to, String body) {
                lastEmailCode = extractCode(body);
            }

            private String extractCode(String body) {
                String marker = "code is: ";
                int idx = body.indexOf(marker);
                if (idx < 0) return null;
                return body.substring(idx + marker.length()).trim();
            }
        };
    }
}
