package com.authservice;

import com.authservice.config.NotificationService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
                Matcher matcher = Pattern.compile("(?i)code is:\\s*(?:<[^>]+>\\s*)*([0-9]{6})")
                        .matcher(body);
                return matcher.find() ? matcher.group(1) : null;
            }
        };
    }
}
