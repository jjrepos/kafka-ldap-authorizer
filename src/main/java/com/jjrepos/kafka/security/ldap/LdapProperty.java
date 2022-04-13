package com.jjrepos.kafka.security.ldap;

public enum LdapProperty {

    URL("ldap.url"),
    BASE_DN("ldap.base.dn"),
    SEARCH_BASE("ldap.search.base"),
    USER("ladp.user"),
    PASSWORD("ldap.password"),
    CACHE_VALIDITY_MILLIS("ldap.auth.cache.validity.millis");

    public final String config;

    LdapProperty(String name) {
        this.config = name;
    }

}
