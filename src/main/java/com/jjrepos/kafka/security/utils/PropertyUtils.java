package com.jjrepos.kafka.security.utils;

import java.util.Map;

public final class PropertyUtils {
    public static String getRequiredStringProperty(final Map<String, ?> configs, final String name) {
        final Object value = configs.get(name);
        if (value == null) {
            throw new IllegalArgumentException("Missing required configuration property \"" + name + "\".");
        }
        return value.toString();
    }

    public static long getRequiredLongProperty(final Map<String, ?> configs, final String name) {
        final Object value = configs.get(name);
        if (value == null) {
            throw new IllegalArgumentException("Missing required configuration property \"" + name + "\".");
        }
        try {
            return Long.parseLong(value.toString());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid configuration property \"" + name + "\".");
        }
    }
}
