package com.jjrepos.kafka.security.ldap;

import com.jjrepos.kafka.security.ldap.authenticator.UsernamePasswordAuthenticator;
import com.jjrepos.kafka.security.ldap.authorizer.GroupsBuilder;
import com.jjrepos.kafka.security.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.*;
import java.util.stream.Stream;

public class LdapConnector implements UsernamePasswordAuthenticator, GroupsBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(LdapConnector.class);
    private static final String MEMBER_OF = "memberOf";
    private static final String CN = "CN";
    private final LdapConfig ldapConfig;
    private final String usernameToDnFormat;

    public LdapConnector(LdapConfig ldapConfig) {
        this.ldapConfig = Objects.requireNonNull(ldapConfig);
        this.usernameToDnFormat = CN + "=%s," + ldapConfig.searchBase() + "," + ldapConfig.baseDn();
        LOG.info("Using user DN format: {}", usernameToDnFormat);
    }

    public boolean authenticate(final String username, final String password) {
        if (StringUtils.isBlank(username) || StringUtils.isBlank(password)) {
            return false;
        }
        LdapContext context = null;
        try {
            final String userDn = String.format(usernameToDnFormat, LdapUtils.escape(username));
            context = bind(userDn, password);
            return true;
        } catch (final AuthenticationException e) {
            LOG.info("Authentication failure for user: {}, {}", username, e.getMessage());
            return false;
        } catch (final NamingException e) {
            throw new LdapException(e);
        } finally {
            if (context != null) {
                try {
                    context.close();
                } catch (final NamingException e) {
                    LOG.warn("Ignoring exception when closing LDAP context.", e);
                }
            }
        }
    }

    public Set<String> groupsForUser(final String user) {
        LdapContext context = null;
        NamingEnumeration<SearchResult> results = null;
        try {
            final String userDn = String.format(usernameToDnFormat, LdapUtils.escape(ldapConfig.bindUser()));
            context = bind(userDn, ldapConfig.bindUserPassword());
            LOG.debug("Authenticated bind user: {}", ldapConfig.bindUser());
            var searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchControls.setTimeLimit(10000);
            searchControls.setReturningAttributes(new String[]{MEMBER_OF});
            var searchFilter = String.format("(CN=%s)", user);
            LOG.trace("Getting groups for user: {}", searchFilter);
            results = context.search(ldapConfig.searchBase(), searchFilter, searchControls);
            var groups = parseGroups(results);
            LOG.debug("User {} is in {} groups", user, groups);
            return groups;
        } catch (final AuthenticationException e) {
            LOG.info("Authentication failure for user: {}, {}", ldapConfig.bindUser(), e.getMessage());
        } catch (final NamingException e) {
            throw new LdapException(e);
        } finally {
            try {
                if (results != null) results.close();
                if (context != null) context.close();
            } catch (final NamingException e) {
                LOG.warn("Ignoring exception when closing LDAP results/context.", e);
            }
        }
        LOG.info("User {} is in not in any groups", user);
        return Collections.emptySet();
    }

    private Set<String> parseGroups(NamingEnumeration<SearchResult> results) throws NamingException {
        Set<String> groups = new HashSet<>(3);
        while (results != null && results.hasMore()) {
            Attribute attribute = results.next().getAttributes().get(MEMBER_OF);
            var memberOf = attribute.getAll();
            while (memberOf.hasMore()) {
                var member = memberOf.next().toString();
                LOG.debug("memberOf from LDAP: {}", member);
                var memberArr = member.split(",");
                Arrays.stream(memberArr)
                        .map(String::toUpperCase)
                        .filter(grp -> grp.startsWith(CN))
                        .map(grp -> grp.split("="))
                        .flatMap(Stream::of)
                        .dropWhile(grp -> grp.equals(CN))
                        .findFirst()
                        .ifPresent(groups::add);
            }
        }
        return groups;
    }

    private InitialLdapContext bind(final String userDn, final String password) throws NamingException {
        final Hashtable<String, Object> env = new Hashtable<>(5);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapConfig.url());
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, userDn);
        env.put(Context.SECURITY_CREDENTIALS, password);
        if (LOG.isTraceEnabled()) env.put("com.sun.jndi.ldap.trace.ber", System.err);
        return new InitialLdapContext(env, null);
    }
}
