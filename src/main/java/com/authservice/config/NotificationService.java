package com.authservice.config;

/**
 * Pluggable notification channel. Default implementation logs to console;
 * swap with SMTP/SMS providers without touching the auth flow.
 */
public interface NotificationService {

    void sendEmail(String to, String subject, String body);

    void sendSms(String to, String body);
}
