package com.jjrepos.kafka.security.ldap.authorizer;

import com.jjrepos.kafka.security.ldap.LdapConfig;

@FunctionalInterface
public interface GroupsBuilderFactory {
    GroupsBuilder create(LdapConfig spec);
}
