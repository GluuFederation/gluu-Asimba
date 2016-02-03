/*
 * Asimba Server
 * 
 * Copyright (C) 2015, Gluu
 * Copyright (C) 2013 Asimba
 * Copyright (C) 2007-2008 Alfa & Ariss B.V.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see www.gnu.org/licenses
 * 
 * gluu-Asimba - Serious Open Source SSO - More information on www.gluu.org
 * 
 */
package org.gluu.authentication.remote.saml2.selector;


import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.gluu.asimba.util.ldap.LDAPUtility;
import org.gluu.site.ldap.LDAPConnectionProvider;
import org.gluu.site.ldap.OperationsFacade;
import org.gluu.site.ldap.persistence.LdapEntryManager;
import org.gluu.asimba.util.ldap.selector.ApplicationSelectorLDAPEntry;


/**
 * LDAP Configuration for application based selector.
 * 
 * @author Dmitry Ognyannikov
 */
public class ApplicationSelectorConfigurationLDAP {

    private static final Log _logger = LogFactory.getLog(ApplicationSelectorConfigurationLDAP.class);

    private Map<String, String> applicationMapping;

    public ApplicationSelectorConfigurationLDAP() {
            applicationMapping = new HashMap<>();
    }

    public synchronized void loadConfiguration() throws OAException {
        final LDAPConnectionProvider provider;
        final OperationsFacade ops;
        final LdapEntryManager ldapEntryManager;

        // connect
        try {
            Properties props = LDAPUtility.getLDAPConfiguration();
            provider = new LDAPConnectionProvider(props);
            ops = new OperationsFacade(provider, null);
            ldapEntryManager = new LdapEntryManager(ops);
        } catch (Exception e) {
            _logger.error("cannot open LDAP", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

        try {
            applicationMapping = loadIdpMapping(ldapEntryManager);
        } catch (Exception e) {
            _logger.error("cannot load LDAP ApplicationSelector settings", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        } finally {
            ldapEntryManager.destroy();
        }
    }

    private Map<String, String> loadIdpMapping(LdapEntryManager ldapEntryManager) throws OAException {
        Map<String, String> result = new HashMap<String, String>();

        final ApplicationSelectorLDAPEntry template = new ApplicationSelectorLDAPEntry();
        List<ApplicationSelectorLDAPEntry> entries = ldapEntryManager.findEntries(template);
        // load LDAP entries
        for (ApplicationSelectorLDAPEntry entry : entries) {
            
            String entityId = entry.getId();
            String organizationId = entry.getOrganizationId();
            
            if (!entry.isEnabled()) {
                _logger.info("ApplicationSelector is disabled. Id: " + entityId + ", organizationId: " + organizationId);
                continue;
            }
            
            if (result.containsKey(entityId)) {
                _logger.error("Dublicated ApplicationSelector. Id: " + entityId + ", organizationId: " + organizationId);
                continue;
            }
            
            _logger.info("ApplicationSelector loaded. Id: " + entityId + ", organizationId: " + organizationId);
            result.put(entityId, organizationId);
        }

        return result;
    }

    public Map<String, String> getApplicationMapping() {
        return applicationMapping;
    }

}

