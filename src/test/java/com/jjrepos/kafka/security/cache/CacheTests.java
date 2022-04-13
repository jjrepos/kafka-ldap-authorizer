package com.jjrepos.kafka.security.cache;

import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

@RunWith(JUnitPlatform.class)
public class CacheTests {
    @Test
    public void getIfValid_should_return_value_when_key_is_present() {
        AuthCache.INSTANCE.put("hello", "world!!!");
        assertTrue(AuthCache.INSTANCE.getIfValid("hello").isPresent());
        AuthCache.INSTANCE.getIfValid("hello")
                .ifPresent(value -> assertEquals(value, "world!!!"));
    }

    @Test
    public void getIfValid_should_return_empty_when_key_is_present_but_expired() throws InterruptedException {
        AuthCache.INSTANCE.put("hello", "world!!!", Duration.ofMillis(10));
        Thread.sleep(15);
        assertTrue(AuthCache.INSTANCE.getIfValid("hello").isEmpty());
    }

    @Test
    public void get_should_return_value_when_key_is_present_but_expired() throws InterruptedException {
        AuthCache.INSTANCE.put("hello", "world!!!", Duration.ofMillis(10));
        Thread.sleep(5);
        assertNotNull(AuthCache.INSTANCE.get("hello"));
        assertEquals(AuthCache.INSTANCE.get("hello"), "world!!!");
    }

    @Test
    public void put_should_cache_value_for_one_day_by_default() throws InterruptedException {
        AuthCache.INSTANCE.put("hello", "world!!!");
        Thread.sleep(5 * 1000);
        assertNotNull(AuthCache.INSTANCE.get("hello"));
        assertEquals(AuthCache.INSTANCE.get("hello"), "world!!!");
    }

    @Test
    public void auth_test_should_have_only_one_instance_per_jvm() {
        Cache cache1 = AuthCache.INSTANCE;
        Cache cache2 = AuthCache.INSTANCE;
        assertSame(cache1, cache2);
    }

}
