package com.jjrepos.kafka.security.ldap;

import com.jjrepos.kafka.security.ldap.authorizer.Groups;
import org.junit.ClassRule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zapodot.junit.ldap.EmbeddedLdapRule;
import org.zapodot.junit.ldap.EmbeddedLdapRuleBuilder;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class LdapConnectorTest {

    static final String BASE_DN = "dc=bah,dc=com";

    private static final Logger LOG = LoggerFactory.getLogger(LdapConnectorTest.class);
    private static final String BIND_USER = "kafka_admin";
    private static final String PASSWORD = "admin#secret";
    @ClassRule
    public static EmbeddedLdapRule LDAP_RULE = EmbeddedLdapRuleBuilder.newInstance()
            .usingDomainDsn(BASE_DN)
            .importingLdifs("ldap/kafka-users.ldif")
            .build();
    private final LdapConfig ldapConnSpec =
            new LdapConfig("ldap://localhost:" + LDAP_RULE.embeddedServerPort(), BASE_DN, "OU=Service Accounts", BIND_USER, PASSWORD);
    private final LdapConnector ldapConnector = new LdapConnector(ldapConnSpec);

    @Test
    public void should_authenticate_admin_user() {
        assertTrue(ldapConnector.authenticate("kafka_admin", "admin#secret"));
    }


    @Test
    public void should_authenticate_super_user() {
        assertTrue(ldapConnector.authenticate("kafka_super_user", "super!secret"));
    }

    @Test
    public void should_authenticate_user() {
        assertTrue(ldapConnector.authenticate("kafka_user", "secret?"));
    }

    @Test
    public void should_fail_wrong_user() {
        assertFalse(ldapConnector.authenticate("kafka_no_user", "greatsecret?"));
    }

    @Test
    public void should_fail_wrong_password() {
        assertFalse(ldapConnector.authenticate("kafka_user", "notasecret?"));
    }


    @Test
    public void should_return_groups_for_user_kafka_broker() {
        Set<String> groups = ldapConnector.groupsForUser("kafka_broker");
        assertFalse(groups.isEmpty());
        assertTrue(groups.contains(Groups.ADMIN.name));
    }

    @Test
    public void should_return_groups_for_user_kafka_user() {
        Set<String> groups = ldapConnector.groupsForUser("kafka_user");
        assertFalse(groups.isEmpty());
        assertTrue(groups.contains(Groups.READ.name));
        assertTrue(groups.contains(Groups.WRITE.name));
    }

    @Test
    public void should_return_groups_for_super_user() {
        Set<String> groups = ldapConnector.groupsForUser("kafka_super_user");
        assertFalse(groups.isEmpty());
        assertTrue(groups.contains(Groups.SUPER_USER.name));
    }

    @Test
    public void should_return_no_groups_for_unknown_user() {
        Set<String> groups = ldapConnector.groupsForUser("unknown_user");
        assertTrue(groups.isEmpty());
    }

    @Test
    public void should_return_no_groups_for_invalid_bind_user() {
        final LdapConfig ldapConnSpec =
                new LdapConfig("ldap://localhost:" + LDAP_RULE.embeddedServerPort(), BASE_DN,
                        "OU=Service Accounts", "unknown_user", "PASSWORD");
        final LdapConnector ldapConnector = new LdapConnector(ldapConnSpec);
        Set<String> groups = ldapConnector.groupsForUser("unknown_user");
        assertTrue(groups.isEmpty());
    }
}
