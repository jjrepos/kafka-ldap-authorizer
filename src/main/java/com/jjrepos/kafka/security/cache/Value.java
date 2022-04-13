package com.jjrepos.kafka.security.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.LocalDateTime;

public class Value<T> implements Cacheable {

    private static final Logger LOG = LoggerFactory.getLogger(Value.class);

    private final Duration duration;
    private final LocalDateTime createdTime;
    private final T value;

    public Value(T value, Duration duration, LocalDateTime createdTime) {
        this.value = value;
        this.duration = duration;
        this.createdTime = createdTime;
        LOG.debug("Cache createdAt: {}, ExpiresAt: {} ", createdTime, duration);
        LOG.debug("Cache expiration: {} ", createdTime.plus(duration));
    }

    @Override
    public LocalDateTime createdTime() {
        return createdTime;
    }

    @Override
    public Duration validity() {
        return duration;
    }

    @Override
    public T get() {
        return value;
    }

}
