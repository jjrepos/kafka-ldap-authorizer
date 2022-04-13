package com.jjrepos.kafka.security.ldap.authenticator;

import com.jjrepos.kafka.security.ldap.LdapProperty;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@RunWith(JUnitPlatform.class)
public class LdapAuthenticateCallbackHandlerTest {

    private static final Logger LOG = LoggerFactory.getLogger(LdapAuthenticateCallbackHandlerTest.class);

    private static final String USERNAME = "user";
    private static final String PASSWORD = "password";
    private final UsernamePasswordAuthenticator authenticator = Mockito.mock(UsernamePasswordAuthenticator.class);


    @Test
    public void should_accept_valid_config() {
        destroyAuthenticateCallbackHandler(configureAuthenticateCallbackHandler());
    }

    @Test
    public void should_not_accept_invalid_sasl_mechanism() {
        Exception e = assertThrows(IllegalArgumentException.class, () ->
                destroyAuthenticateCallbackHandler(configureAuthenticateCallbackHandler("hello")));
        assertTrue(e.getMessage().contains("Only SASL mechanism \"PLAIN\" is supported."));
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
            Exception e = assertThrows(IllegalArgumentException.class, () -> configureAuthenticateCallbackHandler(incompleteConfig, "PLAIN"));
            assert missingConfig != null;
            assertTrue(e.getMessage().contains(missingConfig));
        }
    }

    @Test
    public void should_authenticate_known_user() {
        var handler = configureAuthenticateCallbackHandler();
        when(authenticator.authenticate(USERNAME, PASSWORD)).thenReturn(true);
        var nameCallBack = new NameCallback("prompt", USERNAME);
        var passwordCallBack = new PlainAuthenticateCallback(PASSWORD.toCharArray());
        var callbacks = new Callback[]{nameCallBack, passwordCallBack};
        try {
            handler.handle(callbacks);
        } catch (UnsupportedCallbackException e) {
            fail("Exception is not expected", e);
        }
        destroyAuthenticateCallbackHandler(handler);
    }

    @Test
    public void should_fail_to_authenticate_unknown_user() {
        var handler = configureAuthenticateCallbackHandler();
        when(authenticator.authenticate(USERNAME, PASSWORD)).thenReturn(true);
        var nameCallBack = new NameCallback("prompt", "Hello");
        var passwordCallBack = new PlainAuthenticateCallback(PASSWORD.toCharArray());
        var callbacks = new Callback[]{nameCallBack, passwordCallBack};
        try {
            handler.handle(callbacks);
            assertFalse(passwordCallBack.authenticated());
        } catch (UnsupportedCallbackException e) {
            LOG.error("Encountered unknown error", e);
        }
        destroyAuthenticateCallbackHandler(handler);
    }

    @Test
    public void should_fail_missing_user() {
        var handler = configureAuthenticateCallbackHandler();
        when(authenticator.authenticate(USERNAME, PASSWORD)).thenReturn(true);
        var callbacks = new Callback[]{new PlainAuthenticateCallback(PASSWORD.toCharArray())};
        Exception e = assertThrows(IllegalStateException.class, () -> handler.handle(callbacks));
        assertEquals("Expected NameCallback was not found.", e.getMessage());
        destroyAuthenticateCallbackHandler(handler);
    }

    @Test
    public void should_fail_missing_password() {
        var handler = configureAuthenticateCallbackHandler();
        when(authenticator.authenticate(USERNAME, PASSWORD)).thenReturn(true);
        var callbacks = new Callback[]{new NameCallback("prompt", "Hello")};
        Exception e = assertThrows(IllegalStateException.class, () -> handler.handle(callbacks));
        assertEquals("Expected PlainAuthenticationCallback was not found.", e.getMessage());
        destroyAuthenticateCallbackHandler(handler);
    }

    private LdapAuthenticateCallbackHandler configureAuthenticateCallbackHandler(final Map<String, ?> configs, final String saslMechanism) {
        final LdapAuthenticateCallbackHandler callbackHandler = new LdapAuthenticateCallbackHandler((spec) -> authenticator);
        callbackHandler.close();
        callbackHandler.configure(configs, saslMechanism, Collections.emptyList());
        return callbackHandler;
    }

    private LdapAuthenticateCallbackHandler configureAuthenticateCallbackHandler() {
        return configureAuthenticateCallbackHandler(kafkaConfig(), "PLAIN");
    }

    private LdapAuthenticateCallbackHandler configureAuthenticateCallbackHandler(String saslMechanism) {
        return configureAuthenticateCallbackHandler(kafkaConfig(), saslMechanism);
    }

    private void destroyAuthenticateCallbackHandler(final AuthenticateCallbackHandler handler) {
        handler.close();
    }

    private Callback getUsernameCallback(final String username) {
        return new NameCallback("prompt", username);
    }

    private PlainAuthenticateCallback getPasswordCallback(final char[] password) {
        return new PlainAuthenticateCallback(password);
    }


    private Map<String, Object> kafkaConfig() {
        final Map<String, Object> config = new LinkedHashMap<>();
        config.put(LdapProperty.URL.config, "localhost");
        config.put(LdapProperty.BASE_DN.config, "dc=bah,dc=com");
        config.put(LdapProperty.SEARCH_BASE.config, "OU=Service Accounts");
        return config;
    }

}
