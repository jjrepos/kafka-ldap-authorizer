package com.jjrepos.kafka.security.ldap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LdapConfig {
    private static final Logger LOG = LoggerFactory.getLogger(LdapConfig.class);
    private final String url;
    private final String baseDn;
    private final String searchBase;
    private final String bindUser;
    private final String bindUserPassword;

    public LdapConfig(final String url, final String baseDn, String searchBase, String bindUser, String bindUserPassword) {
        this.url = url;
        this.baseDn = baseDn;
        this.searchBase = searchBase;
        this.bindUser = bindUser;
        this.bindUserPassword = bindUserPassword;
        LOG.info("Initializing LdapConnection url: {}, baseDn: {}, searchBase: {}, bindUser: {}", url, baseDn, searchBase, bindUser);
    }

    public LdapConfig(String url, String baseDn, String searchBase) {
        this.url = url;
        this.baseDn = baseDn;
        this.searchBase = searchBase;
        this.bindUser = null;
        this.bindUserPassword = null;
        LOG.info("Initializing LdapConnection url: {}, baseDn: {}, searchBase: {}", url, baseDn, searchBase);
    }

    public String url() {
        return url + "/" + baseDn;
    }

    public String baseDn() {
        return baseDn;
    }

    public String searchBase() {
        return this.searchBase;
    }

    public String bindUser() {
        return bindUser;
    }

    public String bindUserPassword() {
        return bindUserPassword;
    }
}
