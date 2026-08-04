package com.authservice.config;

import java.time.Duration;
import java.util.Optional;

/**
 * Pluggable OTP key-value store.
 * Redis implementation for production, in-memory for local development.
 */
public interface OtpCodeStore {

    void save(String key, String value, Duration ttl);

    Optional<String> get(String key);

    void delete(String key);
}
