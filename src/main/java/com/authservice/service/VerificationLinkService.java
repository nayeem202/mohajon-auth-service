package com.authservice.service;

import com.authservice.config.OtpCodeStore;
import com.authservice.exception.ApiException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;

/** Generic, single-use email link storage. No business data belongs here. */
@Service
public class VerificationLinkService {

    private static final Duration TTL = Duration.ofHours(24);
    private static final String PREFIX = "email-link:";

    private final OtpCodeStore store;
    private final SecureRandom random = new SecureRandom();

    public VerificationLinkService(OtpCodeStore store) {
        this.store = store;
    }

    public String issue(String email) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        store.save(PREFIX + hash(token), email, TTL);
        return token;
    }

    public String consume(String token) {
        if (token == null || token.isBlank()) {
            throw ApiException.badRequest("INVALID_ACTIVATION_LINK", "This activation link is invalid or expired.");
        }
        String key = PREFIX + hash(token.trim());
        String email = store.get(key).orElseThrow(() ->
                ApiException.badRequest("INVALID_ACTIVATION_LINK", "This activation link is invalid or expired."));
        store.delete(key);
        return email;
    }

    private static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
