package com.jjrepos.kafka.security.ldap.authorizer;

import com.jjrepos.kafka.security.ldap.LdapConnector;
import com.jjrepos.kafka.security.ldap.LdapProperty;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.server.authorizer.Action;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(JUnitPlatform.class)
public class AuthorizerTest {
    private static final Logger LOG = LoggerFactory.getLogger(AuthorizerTest.class);
    private final static LdapConnector ldapConnector = Mockito.mock(LdapConnector.class);
    private static final AuthorizableRequestContext ctx = Mockito.mock(AuthorizableRequestContext.class);

    private static final ResourcePattern TOPIC = new ResourcePattern(ResourceType.TOPIC, "api.facilities.enrich.timezone", PatternType.LITERAL);
    private static final ResourcePattern GROUP = new ResourcePattern(ResourceType.GROUP, "api.facilities.enrich.timezone.consumer.group", PatternType.LITERAL);
    private static final ResourcePattern TRANSACTION_ID = new ResourcePattern(ResourceType.TRANSACTIONAL_ID, "api.facilities.enrich.timezone.transaction.id", PatternType.LITERAL);
    private static final ResourcePattern CLUSTER = new ResourcePattern(ResourceType.CLUSTER, "kafka.server01.bah.com", PatternType.LITERAL);

    private static final Action READ_TOPIC = Mockito.mock(Action.class);
    private static final Action WRITE_TOPIC = Mockito.mock(Action.class);

    private static final Action CREATE_TOPIC = Mockito.mock(Action.class);
    private static final Action DELETE_TOPIC = Mockito.mock(Action.class);
    private static final Action ALTER_TOPIC = Mockito.mock(Action.class);

    private static final Action GROUP_READ = Mockito.mock(Action.class);
    private static final Action GROUP_DELETE = Mockito.mock(Action.class);
    private static final Action GROUP_DESCRIBE = Mockito.mock(Action.class);
    private static final Action TRANSACTION_DESCRIBE = Mockito.mock(Action.class);
    private static final Action TRANSACTION_WRITE = Mockito.mock(Action.class);

    private static final Action CLUSTER_ALTER = Mockito.mock(Action.class);
    private static final Action ALTER_CONFIG = Mockito.mock(Action.class);
    private static final Action CLUSTER_ACTION = Mockito.mock(Action.class);
    private static final Action DESCRIBE_CLUSTER_CONFIG = Mockito.mock(Action.class);
    private static final Action IDEMPOTENT_WRITE = Mockito.mock(Action.class);

    private static final Set<String> ADMIN_GROUP = Collections.singleton(Groups.ADMIN.name);
    private static final Set<String> SUPER_USER_GROUP = Collections.singleton(Groups.SUPER_USER.name);
    private static final Set<String> READ_GROUP = Collections.singleton(Groups.READ.name);
    private static final Set<String> WRITE_GROUP = new HashSet<>(Collections.singletonList(Groups.WRITE.name));
    private static final Set<String> RW_GROUP = new HashSet<>(Arrays.asList(Groups.READ.name, Groups.WRITE.name));

    private static final KafkaPrincipal principal = Mockito.mock(KafkaPrincipal.class);

    private final LdapAuthorizer authorizer = configureLdapAuthorizer(kafkaConfig());


    static void setupForClusterOps() {
        when(CLUSTER_ACTION.resourcePattern()).thenReturn(CLUSTER);
        when(CLUSTER_ACTION.operation()).thenReturn(AclOperation.CLUSTER_ACTION);

        when(CLUSTER_ALTER.resourcePattern()).thenReturn(CLUSTER);
        when(CLUSTER_ALTER.operation()).thenReturn(AclOperation.ALTER);

        when(ALTER_CONFIG.resourcePattern()).thenReturn(CLUSTER);
        when(ALTER_CONFIG.operation()).thenReturn(AclOperation.ALTER_CONFIGS);

        when(DESCRIBE_CLUSTER_CONFIG.resourcePattern()).thenReturn(CLUSTER);
        when(DESCRIBE_CLUSTER_CONFIG.operation()).thenReturn(AclOperation.DESCRIBE_CONFIGS);

        when(IDEMPOTENT_WRITE.resourcePattern()).thenReturn(CLUSTER);
        when(IDEMPOTENT_WRITE.operation()).thenReturn(AclOperation.IDEMPOTENT_WRITE);
    }

    static void setupForTransactionWrite() {
        when(TRANSACTION_WRITE.resourcePattern()).thenReturn(TRANSACTION_ID);
        when(TRANSACTION_WRITE.operation()).thenReturn(AclOperation.WRITE);
    }

    static void setupForTransactionDescribe() {
        when(TRANSACTION_DESCRIBE.resourcePattern()).thenReturn(TRANSACTION_ID);
        when(TRANSACTION_DESCRIBE.operation()).thenReturn(AclOperation.DESCRIBE);
    }

    static void setupForTopicRead() {
        when(READ_TOPIC.resourcePattern()).thenReturn(TOPIC);
        when(READ_TOPIC.operation()).thenReturn(AclOperation.READ);
    }

    static void setupForGroupRead() {
        when(GROUP_READ.resourcePattern()).thenReturn(GROUP);
        when(GROUP_READ.operation()).thenReturn(AclOperation.READ);
    }

    static void setupForGroupDelete() {
        when(GROUP_DELETE.resourcePattern()).thenReturn(GROUP);
        when(GROUP_DELETE.operation()).thenReturn(AclOperation.DELETE);
    }

    static void setupForGroupDescribe() {
        when(GROUP_DESCRIBE.resourcePattern()).thenReturn(GROUP);
        when(GROUP_DESCRIBE.operation()).thenReturn(AclOperation.DESCRIBE);
    }

    static void setupForTopicWrite() {
        when(WRITE_TOPIC.resourcePattern()).thenReturn(TOPIC);
        when(WRITE_TOPIC.operation()).thenReturn(AclOperation.WRITE);
    }

    static void setupForTopicDelete() {
        when(DELETE_TOPIC.resourcePattern()).thenReturn(TOPIC);
        when(DELETE_TOPIC.operation()).thenReturn(AclOperation.DELETE);
    }

    static void setupForTopicCreate() {
        when(CREATE_TOPIC.resourcePattern()).thenReturn(TOPIC);
        when(CREATE_TOPIC.operation()).thenReturn(AclOperation.CREATE);
    }

    static void setupForTopicAlter() {
        when(ALTER_TOPIC.resourcePattern()).thenReturn(TOPIC);
        when(ALTER_TOPIC.operation()).thenReturn(AclOperation.ALTER);
    }

    @BeforeAll
    static void setup() {
        setupForTopicRead();
        setupForTopicWrite();
        setupForTopicDelete();
        setupForTopicCreate();
        setupForTopicAlter();

        setupForGroupRead();
        setupForGroupDescribe();
        setupForGroupDelete();

        setupForTransactionWrite();
        setupForTransactionDescribe();

        setupForClusterOps();
    }

    @Test
    public void authorize_kafka_user_should_allow_topic_read_write_group_read_describe_transaction_write_describe() {
        List<Action> actions = Arrays.asList(READ_TOPIC, WRITE_TOPIC, GROUP_READ, GROUP_DESCRIBE,
                TRANSACTION_DESCRIBE, TRANSACTION_WRITE);
        when(ctx.principal()).thenReturn(principal);
        when(principal.getName()).thenReturn("kafka_rw_user");
        when(ldapConnector.groupsForUser(any())).thenReturn(RW_GROUP);
        List<AuthorizationResult> results = authorizer.authorize(ctx, actions);
        LOG.debug("{}", results);
        assertNotNull(results);
        assertEquals(results.size(), actions.size());
        results.forEach(result -> assertEquals(AuthorizationResult.ALLOWED, result));
    }

    @Test
    public void authorize_read_user_should_allow_read() {
        List<Action> actions = Collections.singletonList(READ_TOPIC);
        when(ctx.principal()).thenReturn(principal);
        when(principal.getName()).thenReturn("kafka_read_only_user");
        when(ldapConnector.groupsForUser(any())).thenReturn(READ_GROUP);
        List<AuthorizationResult> results = authorizer.authorize(ctx, actions);
        assertNotNull(results);
        assertEquals(results.size(), actions.size());
        results.forEach(result -> assertEquals(AuthorizationResult.ALLOWED, result));
    }

    @Test
    public void authorize_read_user_should_not_allow_write() {
        List<Action> actions = Arrays.asList(WRITE_TOPIC, TRANSACTION_DESCRIBE, TRANSACTION_WRITE);
        when(ctx.principal()).thenReturn(principal);
        when(principal.getName()).thenReturn("kafka_read_only_user");
        when(ldapConnector.groupsForUser(any())).thenReturn(READ_GROUP);
        List<AuthorizationResult> results = authorizer.authorize(ctx, actions);
        assertNotNull(results);
        assertEquals(results.size(), actions.size());
        results.forEach(result -> assertEquals(AuthorizationResult.DENIED, result));
    }

    @Test
    public void authorize_write_user_should_allow_write() {
        List<Action> actions = Arrays.asList(WRITE_TOPIC, TRANSACTION_DESCRIBE, TRANSACTION_WRITE);
        when(ctx.principal()).thenReturn(principal);
        when(principal.getName()).thenReturn("kafka_write_user");
        when(ldapConnector.groupsForUser(any())).thenReturn(WRITE_GROUP);
        List<AuthorizationResult> results = authorizer.authorize(ctx, actions);
        assertNotNull(results);
        assertEquals(results.size(), actions.size());
        results.forEach(result -> assertEquals(AuthorizationResult.ALLOWED, result));
    }

    @Test
    public void authorize_write_user_should_not_allow_read() {
        List<Action> actions = Collections.singletonList(READ_TOPIC);
        when(ctx.principal()).thenReturn(principal);
        when(principal.getName()).thenReturn("kafka_write_user");
        when(ldapConnector.groupsForUser(any())).thenReturn(WRITE_GROUP);
        List<AuthorizationResult> results = authorizer.authorize(ctx, actions);
        assertNotNull(results);
        assertEquals(results.size(), actions.size());
        results.forEach(result -> assertEquals(AuthorizationResult.DENIED, result));
    }


    @Test
    public void authorize_kafka_rw_user_should_fail_topic_create() {
        List<Action> actions = Arrays.asList(READ_TOPIC, WRITE_TOPIC, CREATE_TOPIC);
        when(ctx.principal()).thenReturn(principal);
        when(principal.getName()).thenReturn("kafka_rw_user");
        when(ldapConnector.groupsForUser(any())).thenReturn(RW_GROUP);
        List<AuthorizationResult> results = authorizer.authorize(ctx, actions);
        assertNotNull(results);
        assertEquals(results.size(), actions.size());
        assertTrue(results.contains(AuthorizationResult.DENIED));
    }

    @Test
    public void authorize_kafka_rw_user_should_fail_topic_alter() {
        List<Action> actions = Arrays.asList(READ_TOPIC, WRITE_TOPIC, ALTER_TOPIC);
        when(ctx.principal()).thenReturn(principal);
        when(principal.getName()).thenReturn("kafka_rw_user");
        when(ldapConnector.groupsForUser(any())).thenReturn(RW_GROUP);
        List<AuthorizationResult> results = authorizer.authorize(ctx, actions);
        assertNotNull(results);
        assertEquals(results.size(), actions.size());
        assertTrue(results.contains(AuthorizationResult.DENIED));
    }

    @Test
    public void authorize_kafka_rw_user_should_fail_topic_delete() {
        List<Action> actions = Arrays.asList(READ_TOPIC, WRITE_TOPIC, DELETE_TOPIC);
        when(ctx.principal()).thenReturn(principal);
        when(principal.getName()).thenReturn("kafka_rw_user");
        when(ldapConnector.groupsForUser(any())).thenReturn(RW_GROUP);
        List<AuthorizationResult> results = authorizer.authorize(ctx, actions);
        assertNotNull(results);
        assertEquals(results.size(), actions.size());
        assertTrue(results.contains(AuthorizationResult.DENIED));
    }

    @Test
    public void authorize_super_user_should_allow_all_topic_group_transaction_ops() {
        List<Action> actions = Arrays.asList(READ_TOPIC, WRITE_TOPIC, CREATE_TOPIC, ALTER_TOPIC, DELETE_TOPIC,
                GROUP_READ, GROUP_DESCRIBE, GROUP_DELETE, TRANSACTION_WRITE, TRANSACTION_DESCRIBE);
        when(ctx.principal()).thenReturn(principal);
        when(principal.getName()).thenReturn("kafka_super_user");
        when(ldapConnector.groupsForUser(any())).thenReturn(SUPER_USER_GROUP);
        List<AuthorizationResult> results = authorizer.authorize(ctx, actions);
        assertNotNull(results);
        assertEquals(results.size(), actions.size());
        results.forEach(result -> assertEquals(AuthorizationResult.ALLOWED, result));
    }

    @Test
    public void authorize_admin_user_should_allow_all_ops() {
        List<Action> actions = Arrays.asList(CLUSTER_ACTION, ALTER_CONFIG, CLUSTER_ALTER,
                DESCRIBE_CLUSTER_CONFIG, IDEMPOTENT_WRITE, READ_TOPIC, ALTER_TOPIC, WRITE_TOPIC,
                TRANSACTION_WRITE, DELETE_TOPIC, GROUP_DELETE, GROUP_DESCRIBE, GROUP_READ);
        when(ctx.principal()).thenReturn(principal);
        when(principal.getName()).thenReturn("kafka_admin_user");
        when(ldapConnector.groupsForUser(any())).thenReturn(ADMIN_GROUP);
        List<AuthorizationResult> results = authorizer.authorize(ctx, actions);
        assertNotNull(results);
        assertEquals(results.size(), actions.size());
        results.forEach(result -> assertEquals(AuthorizationResult.ALLOWED, result));
    }

    @Test
    public void should_accept_valid_config() {
        configureLdapAuthorizer(kafkaConfig()).close();
    }

    @Test
    public void should_not_accept_missing_config() {
        var configs = kafkaConfig();
        for (int entryIndex = 0; entryIndex < configs.size(); entryIndex++) {
            final Map<String, Object> incompleteConfig = new HashMap<>();
            String missingConfig = null;
            int missingEntryIndex = 0;
            for (var entry : configs.entrySet()) {
                if (missingEntryIndex++ == entryIndex) {
                    missingConfig = entry.getKey();
                    continue;
                }
                incompleteConfig.put(entry.getKey(), entry.getValue());
            }
            Exception e = assertThrows(IllegalArgumentException.class, () -> configureLdapAuthorizer(incompleteConfig));
            assert missingConfig != null;
            assertTrue(e.getMessage().contains(missingConfig));
        }
    }


    private Map<String, Object> kafkaConfig() {
        final Map<String, Object> config = new LinkedHashMap<>();
        config.put(LdapProperty.URL.config, "localhost");
        config.put(LdapProperty.BASE_DN.config, "dc=bah,dc=com");
        config.put(LdapProperty.SEARCH_BASE.config, "OU=Service Accounts");
        config.put(LdapProperty.USER.config, "kafka_test");
        config.put(LdapProperty.PASSWORD.config, "password");
        config.put(LdapProperty.CACHE_VALIDITY_MILLIS.config, "86400000");
        return config;
    }

    private LdapAuthorizer configureLdapAuthorizer(Map<String, Object> config) {
        LdapAuthorizer authorizer = new LdapAuthorizer((spec) -> ldapConnector);
        authorizer.configure(config);
        return authorizer;
    }


}
