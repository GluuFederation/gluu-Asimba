/*
 * oxAsimba is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2015, Gluu
 */
package org.gluu.asimba.util.ldap;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import java.util.List;
import java.util.Properties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.gluu.site.ldap.LDAPConnectionProvider;
import org.gluu.site.ldap.OperationsFacade;
import org.gluu.site.ldap.persistence.LdapEntryManager;

/**
 * Load IDPs from LDAP.
 * 
 * @author Dmitry Ognyannikov
 */
public class LDAPConfigurationLoader {
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

    /**
     * @return the idpEntries
     */
    public List<LdapIDPEntry> getIdpEntries() {
        return idpEntries;
    }
}
