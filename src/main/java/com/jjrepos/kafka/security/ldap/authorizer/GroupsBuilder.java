package com.jjrepos.kafka.security.ldap.authorizer;

import java.util.Set;

public interface GroupsBuilder {
    Set<String> groupsForUser(String user);
}
