package com.jjrepos.kafka.security.utils;

public final class StringUtils {
    public static boolean isBlank(final String s) {
        return s == null || s.trim().length() == 0;
    }
}
