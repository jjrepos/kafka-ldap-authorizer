package com.jjrepos.kafka.security.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

final class InMemoryCache implements Cache {
    private static final Logger LOG = LoggerFactory.getLogger(InMemoryCache.class);

    private static final Duration ONE_DAY = Duration.ofDays(1);
    private final ConcurrentHashMap<String, Cacheable> cache = new ConcurrentHashMap<>();

    public <T> T get(String key) {
        Cacheable value = cache.get(key);
        return value == null ? null : value.get();
    }


    public <T> void put(String key, T cacheable, Duration validity) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(cacheable);
        Objects.requireNonNull(validity);
        Cacheable value = new Value<>(cacheable, validity, LocalDateTime.now());
        cache.put(key, value);
    }

    public <T> void put(String key, T cacheable) {
        put(key, cacheable, ONE_DAY);
    }


    public boolean isValid(String key) {
        Cacheable cacheable = cache.get(key);
        if (cacheable == null) return false;
        var createdAt = cacheable.createdTime();
        var expiresAt = createdAt.plus(cacheable.validity());
        return createdAt.isBefore(expiresAt);
    }

    public <T> Optional<T> getIfValid(String key) {
        Cacheable cacheable = cache.get(key);
        LOG.debug("In cache? :  {} ", cacheable != null);
        if (cacheable == null) return Optional.empty();
        var expiresAt = cacheable.createdTime().plus(cacheable.validity());
        LOG.debug("Cache ExpiresAt: {} ", expiresAt);
        var valid = LocalDateTime.now().isBefore(expiresAt);
        LOG.debug("Cached value valid? :  {} ", valid);
        return valid ? Optional.of(cacheable.get()) : Optional.empty();
    }
}
