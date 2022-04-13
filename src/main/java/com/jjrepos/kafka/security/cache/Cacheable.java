package com.jjrepos.kafka.security.cache;

import java.time.Duration;
import java.time.LocalDateTime;

public interface Cacheable {
    LocalDateTime createdTime();

    Duration validity();

    <T> T get();
}
