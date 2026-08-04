package com.authservice.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

@Component
@ConditionalOnProperty(name = "app.otp.store", havingValue = "redis")
public class RedisOtpCodeStore implements OtpCodeStore {

    private static final String PREFIX = "auth:otp:";

    private final StringRedisTemplate redis;

    public RedisOtpCodeStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public void save(String key, String value, Duration ttl) {
        redis.opsForValue().set(PREFIX + key, value, ttl);
    }

    @Override
    public Optional<String> get(String key) {
        return Optional.ofNullable(redis.opsForValue().get(PREFIX + key));
    }

    @Override
    public void delete(String key) {
        redis.delete(PREFIX + key);
    }
}
