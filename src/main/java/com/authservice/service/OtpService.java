package com.authservice.service;

import com.authservice.config.OtpCodeStore;
import com.authservice.exception.ApiException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Optional;

@Service
public class OtpService {

    private final OtpCodeStore otpCodeStore;
    private final Duration ttl;
    private final int maxAttempts;
    private final Duration cooldown;
    private final SecureRandom random = new SecureRandom();

    public OtpService(
            OtpCodeStore otpCodeStore,
            @Value("${app.otp.ttl:5m}") Duration ttl,
            @Value("${app.otp.max-attempts:5}") int maxAttempts,
            @Value("${app.otp.cooldown:30s}") Duration cooldown) {
        this.otpCodeStore = otpCodeStore;
        this.ttl = ttl;
        this.maxAttempts = maxAttempts;
        this.cooldown = cooldown;
    }

    public String generateAndStore(String key) {
        readEntry(key).ifPresent(entry -> {
            long remaining = entry.sentAt() + cooldown.toMillis() - System.currentTimeMillis();
            if (cooldown.toMillis() > 0 && remaining > 0) {
                throw ApiException.tooManyRequests(
                        "OTP_RATE_LIMITED",
                        "Too many requests. Try again in " + ((remaining / 1000) + 1) + " seconds.");
            }
        });
        String code = String.format("%06d", random.nextInt(1_000_000));
        otpCodeStore.save(key, code + "|0|" + System.currentTimeMillis(), ttl);
        return code;
    }

    public boolean exists(String key) {
        return readEntry(key).isPresent();
    }

    public void verify(String key, String code) {
        Entry entry = readEntry(key)
                .orElseThrow(() -> ApiException.badRequest("INVALID_OTP", "The code is invalid or has expired."));
        if (!constantTimeEquals(code, entry.code())) {
            int attempts = entry.attempts() + 1;
            if (attempts >= maxAttempts) {
                otpCodeStore.delete(key);
                throw ApiException.badRequest("TOO_MANY_ATTEMPTS", "Too many attempts. Request a new code.");
            }
            otpCodeStore.save(key, entry.code() + "|" + attempts + "|" + entry.sentAt(), ttl);
            throw ApiException.badRequest("INVALID_OTP", "The code is incorrect.");
        }
        otpCodeStore.delete(key);
    }

    private Optional<Entry> readEntry(String key) {
        String raw = otpCodeStore.get(key).orElse(null);
        if (raw == null) return Optional.empty();
        String[] parts = raw.split("\\|");
        if (parts.length < 2 || parts.length > 3) {
            otpCodeStore.delete(key);
            return Optional.empty();
        }
        try {
            int attempts = Integer.parseInt(parts[1]);
            long sentAt = parts.length == 3 ? Long.parseLong(parts[2]) : 0L;
            return Optional.of(new Entry(parts[0], attempts, sentAt));
        } catch (NumberFormatException e) {
            otpCodeStore.delete(key);
            return Optional.empty();
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }

    private record Entry(String code, int attempts, long sentAt) {}
}