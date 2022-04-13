package com.jjrepos.kafka.security.ldap.authenticator;

public interface UsernamePasswordAuthenticator {
    boolean authenticate(String username, String password);
}
