package com.jjrepos.kafka.security.ldap.authenticator;

import com.jjrepos.kafka.security.cache.AuthCache;
import com.jjrepos.kafka.security.ldap.LdapConfig;
import com.jjrepos.kafka.security.ldap.LdapConnector;
import com.jjrepos.kafka.security.ldap.LdapProperty;
import com.jjrepos.kafka.security.utils.PropertyUtils;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class LdapAuthenticateCallbackHandler implements AuthenticateCallbackHandler {

    private static final Logger LOG = LoggerFactory.getLogger(LdapAuthenticateCallbackHandler.class);


    private static final String SASL_PLAIN = "PLAIN";
    private final UsernamePasswordAuthenticationFactory authenticationFactory;

    private UsernamePasswordAuthenticator authenticator;

    public LdapAuthenticateCallbackHandler(UsernamePasswordAuthenticationFactory authenticationFactory) {
        this.authenticationFactory = Objects.requireNonNull(authenticationFactory);
    }

    public LdapAuthenticateCallbackHandler() {
        this.authenticationFactory = LdapConnector::new;
    }

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        if (!SASL_PLAIN.equals(saslMechanism)) {
            throw new IllegalArgumentException("Only SASL mechanism \"" + SASL_PLAIN + "\" is supported.");
        }
        configure(configs);
    }

    @Override
    public void close() {
        LOG.info("Closing LDAP Authentication Handler...");
    }

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        if (authenticator == null) {
            throw new IllegalStateException("Ldap authentication handler not properly configured.");
        }
        String username = null;
        PlainAuthenticateCallback plainAuthenticateCallback = null;
        for (final Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                username = ((NameCallback) callback).getDefaultName();
            } else if (callback instanceof PlainAuthenticateCallback) {
                plainAuthenticateCallback = (PlainAuthenticateCallback) callback;
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
        if (username == null) {
            throw new IllegalStateException("Expected NameCallback was not found.");
        }
        if (plainAuthenticateCallback == null) {
            throw new IllegalStateException("Expected PlainAuthenticationCallback was not found.");
        }

        final boolean cached = AuthCache.INSTANCE.isValid(username);
        if (cached) {
            LOG.info("User '{}' in cache, authenticated.", username);
            plainAuthenticateCallback.authenticated(true);
            return;
        }
        final boolean authenticated = authenticator.authenticate(username, String.valueOf(plainAuthenticateCallback.password()));
        if (authenticated) {
            LOG.info("User '{}' authenticated.", username);
        } else {
            LOG.warn("Authentication failed for user '{}'", username);
        }
        plainAuthenticateCallback.authenticated(authenticated);
    }


    private void configure(final Map<String, ?> configs) {
        final String host = PropertyUtils.getRequiredStringProperty(configs, LdapProperty.URL.config);
        final String baseDn = PropertyUtils.getRequiredStringProperty(configs, LdapProperty.BASE_DN.config);
        final String searchBase = PropertyUtils.getRequiredStringProperty(configs, LdapProperty.SEARCH_BASE.config);
        authenticator = authenticationFactory.create(new LdapConfig(host, baseDn, searchBase));
        LOG.info("Configured LDAP authentication plugin...");
    }
}
