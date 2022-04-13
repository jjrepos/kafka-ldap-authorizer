package com.jjrepos.kafka.security.cache;

import java.time.Duration;
import java.util.Optional;

public interface Cache {
    <T> T get(String key);

    <T> void put(String key, T cacheable, Duration validity);

    <T> void put(String key, T cacheable);

    boolean isValid(String key);

    <T> Optional<T> getIfValid(String key);

}
