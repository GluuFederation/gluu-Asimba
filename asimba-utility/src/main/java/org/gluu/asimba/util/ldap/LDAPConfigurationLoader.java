/*
 * Asimba Server
 * 
 * Copyright (c) 2015, Gluu
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
package org.gluu.asimba.util.ldap;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import java.util.List;
import java.util.Properties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.gluu.site.ldap.LDAPConnectionProvider;
import org.gluu.site.ldap.OperationsFacade;
import org.gluu.site.ldap.persistence.LdapEntryManager;
import org.w3c.dom.Element;

/**
 * Load IDPs from LDAP.
 * 
 * @author Dmitry Ognyannikov
 */
public class LDAPConfigurationLoader implements IComponent {
    private static final Log _logger = LogFactory.getLog(LDAPConfigurationLoader.class);
    
    private List<LdapIDPEntry> idpEntries;
    
    public LDAPConfigurationLoader() {}
    
    public void loadConfiguration(Properties props) throws OAException {
        LDAPConnectionProvider provider;
        OperationsFacade ops;
        LdapEntryManager ldapEntryManager;
        
        // connect
        try {
            provider = new LDAPConnectionProvider(props);
            ops = new OperationsFacade(provider, null);
            ldapEntryManager = new LdapEntryManager(ops);
        } catch (Exception e) {
            _logger.error("cannot open LDAP", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        // load IDPs
        try {
//            final LdapConfigurationEntry m = new LdapConfigurationEntry();
//            final List<LdapConfigurationEntry> configurationEntries = ldapEntryManager.findEntries(m);
//            
//            for (LdapConfigurationEntry ldapConfigurationEntry: configurationEntries) {
//                
//            }
            
            final LdapIDPEntry template = new LdapIDPEntry();
            idpEntries = ldapEntryManager.findEntries(template);
            
            for (LdapIDPEntry ldapIDPEntry: idpEntries) {
                _logger.info("Loaded IDPEntry from LDAP: " + ldapIDPEntry.getId() + " : " + ldapIDPEntry.getFriendlyName());
            }
        } catch (Exception e) {
            _logger.error("cannot load LDAP IDPs settings", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        } finally {
            ldapEntryManager.destroy();
        }
    }

    @Override
    public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws OAException {
        //throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public void restart(Element eConfig) throws OAException {
        //throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public void stop() {
        //throw new UnsupportedOperationException("Not supported yet."); 
    }

    /**
     * @return the idpEntries
     */
    public List<LdapIDPEntry> getIdpEntries() {
        return idpEntries;
    }
}
