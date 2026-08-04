package com.authservice.service;

import com.authservice.config.OtpCodeStore;
import com.authservice.exception.ApiException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;

@Service
public class OtpService {

    private final OtpCodeStore otpCodeStore;
    private final Duration ttl;
    private final int maxAttempts;
    private final SecureRandom random = new SecureRandom();

    public OtpService(
            OtpCodeStore otpCodeStore,
            @Value("${app.otp.ttl:5m}") Duration ttl,
            @Value("${app.otp.max-attempts:5}") int maxAttempts) {
        this.otpCodeStore = otpCodeStore;
        this.ttl = ttl;
        this.maxAttempts = maxAttempts;
    }

    public String generateAndStore(String key) {
        String code = String.format("%06d", random.nextInt(1_000_000));
        otpCodeStore.save(key, code + "|0", ttl);
        return code;
    }

    public void verify(String key, String code) {
        String stored = otpCodeStore.get(key)
                .orElseThrow(() -> ApiException.badRequest("INVALID_OTP", "The code is invalid or has expired."));

        String[] parts = stored.split("\\|");
        if (parts.length != 2) {
            otpCodeStore.delete(key);
            throw ApiException.badRequest("INVALID_OTP", "The code is invalid or has expired.");
        }

        if (!parts[0].equals(code)) {
            int attempts = Integer.parseInt(parts[1]) + 1;
            if (attempts >= maxAttempts) {
                otpCodeStore.delete(key);
                throw ApiException.badRequest("TOO_MANY_ATTEMPTS", "Too many attempts. Request a new code.");
            }
            otpCodeStore.save(key, parts[0] + "|" + attempts, ttl);
            throw ApiException.badRequest("INVALID_OTP", "The code is incorrect.");
        }

        otpCodeStore.delete(key);
    }
}
