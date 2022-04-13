package com.jjrepos.kafka.security.ldap.authenticator;

import com.jjrepos.kafka.security.ldap.LdapConfig;

@FunctionalInterface
public interface UsernamePasswordAuthenticationFactory {
    UsernamePasswordAuthenticator create(LdapConfig spec);
}
