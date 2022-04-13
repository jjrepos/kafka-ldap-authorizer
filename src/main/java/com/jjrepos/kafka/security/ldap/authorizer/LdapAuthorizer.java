package com.jjrepos.kafka.security.ldap.authorizer;

import com.jjrepos.kafka.security.cache.AuthCache;
import com.jjrepos.kafka.security.ldap.LdapConfig;
import com.jjrepos.kafka.security.ldap.LdapConnector;
import com.jjrepos.kafka.security.ldap.LdapProperty;
import com.jjrepos.kafka.security.utils.PropertyUtils;
import org.apache.kafka.common.Endpoint;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclBindingFilter;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.server.authorizer.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;

public class LdapAuthorizer implements Authorizer {
    private static final Logger LOG = LoggerFactory.getLogger(LdapAuthorizer.class);

    private final GroupsBuilderFactory groupsBuilderFactory;

    private GroupsBuilder groupsBuilder;
    private Duration cacheValidity;

    public LdapAuthorizer() {
        this.groupsBuilderFactory = LdapConnector::new;
    }

    public LdapAuthorizer(GroupsBuilderFactory groupsBuilderFactory) {
        this.groupsBuilderFactory = Objects.requireNonNull(groupsBuilderFactory);
    }

    @Override
    public Map<Endpoint, ? extends CompletionStage<Void>> start(AuthorizerServerInfo serverInfo) {
        return Collections.emptyMap();
    }

    @Override
    public List<AuthorizationResult> authorize(AuthorizableRequestContext ctx, List<Action> actions) {
        String user = ctx.principal().getName();
        LOG.debug("Authorizing user: {}", user);
        Optional<Set<String>> optional = AuthCache.INSTANCE.getIfValid(user);
        final Set<String> groups = optional.orElseGet(() ->
        {
            LOG.debug("Groups not in cache for user: {}, reaching for ldap...", user);
            Set<String> ldapGroups = groupsBuilder.groupsForUser(user);
            AuthCache.INSTANCE.put(user, ldapGroups, cacheValidity);
            return ldapGroups;
        });
        if (groups.isEmpty()) return denyAll(actions);
        List<GroupAction> groupActions = groups.stream()
                .map(Groups::valueOfName)
                .filter(Objects::nonNull)
                .map(group -> group.groupActions)
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
        LOG.debug("User {} can perform: {}, requested actions: {} ", user, groupActions, actions);
        return allowOnly(groupActions, actions);
    }

    @Override
    public List<? extends CompletionStage<AclCreateResult>> createAcls(AuthorizableRequestContext requestContext, List<AclBinding> aclBindings) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<? extends CompletionStage<AclDeleteResult>> deleteAcls(AuthorizableRequestContext requestContext, List<AclBindingFilter> aclBindingFilters) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Iterable<AclBinding> acls(AclBindingFilter filter) {
        throw new UnsupportedOperationException();
    }


    private List<AuthorizationResult> allowOnly(List<GroupAction> groupActions, List<Action> actions) {
        return actions.stream()
                .map(action -> canPerformAction(groupActions, action) ? AuthorizationResult.ALLOWED : AuthorizationResult.DENIED)
                .collect(Collectors.toList());
    }

    private boolean canPerformAction(List<GroupAction> groupActions, Action action) {
        return groupActions.stream()
                .filter(ga -> ga.resourceType() == ResourceType.ANY || ga.resourceType() == action.resourcePattern().resourceType())
                .anyMatch(ga -> ga.operation() == AclOperation.ALL || ga.operation() == AclOperation.ANY || ga.operation() == action.operation());
    }

    private List<AuthorizationResult> denyAll(List<Action> actions) {
        return actions.stream()
                .map(action -> AuthorizationResult.DENIED)
                .collect(Collectors.toList());
    }

    @Override
    public void close() {
        LOG.info("Closing LdapAuthorizer...");
    }

    @Override
    public void configure(Map<String, ?> configs) {
        LOG.info("configuring LdapAuthorizer plugin...");
        final String host = PropertyUtils.getRequiredStringProperty(configs, LdapProperty.URL.config);
        final String baseDn = PropertyUtils.getRequiredStringProperty(configs, LdapProperty.BASE_DN.config);
        final String searchBase = PropertyUtils.getRequiredStringProperty(configs, LdapProperty.SEARCH_BASE.config);
        final String bindUser = PropertyUtils.getRequiredStringProperty(configs, LdapProperty.USER.config);
        final String bindPassword = PropertyUtils.getRequiredStringProperty(configs, LdapProperty.PASSWORD.config);
        cacheValidity = Duration.ofMillis(PropertyUtils.getRequiredLongProperty(configs, LdapProperty.CACHE_VALIDITY_MILLIS.config));
        groupsBuilder = groupsBuilderFactory.create(new LdapConfig(host, baseDn, searchBase, bindUser, bindPassword));
        LOG.info("Configured LdapAuthorizer...");
        LOG.info("Configured to use bind user {} for searching LDAP groups.", bindUser);
        LOG.info("Configured to cache auth groups for {} millis.", cacheValidity.toMillis());
    }
}
