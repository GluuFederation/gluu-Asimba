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
package org.gluu.asimba.util.ldap;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import java.io.File;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.gluu.asimba.util.ldap.idp.IDPEntry;
import org.gluu.asimba.util.ldap.idp.LdapIDPEntry;
import org.gluu.asimba.util.ldap.selector.ApplicationSelectorEntry;
import org.gluu.asimba.util.ldap.selector.LDAPApplicationSelectorEntry;
import org.gluu.asimba.util.ldap.sp.LDAPRequestorEntry;
import org.gluu.asimba.util.ldap.sp.LDAPRequestorPoolEntry;
import org.gluu.asimba.util.ldap.sp.RequestorEntry;
import org.gluu.asimba.util.ldap.sp.RequestorPoolEntry;
import org.gluu.site.ldap.LDAPConnectionProvider;
import org.gluu.site.ldap.OperationsFacade;
import org.gluu.site.ldap.persistence.LdapEntryManager;
import org.xdi.util.StringHelper;

/**
 * LDAP utility functions.
 * 
 * @author Dmitry Ognyannikov
 */
public class LDAPUtility {
    
    private static final Log log = LogFactory.getLog(LDAPUtility.class);
    
    private static final String ASIMBA_LDAP_CONFIGURATION_FILENAME = "oxasimba-ldap.properties";
    
    private static final LdapEntryManager ldapEntryManager = getLDAPEntryManagerSafe();
    
    public static String getLDAPConfigurationFilePath() {
        String tomcatHome = System.getProperty("catalina.home");
        if (tomcatHome == null) {
            log.error("Failed to load configuration from '" + ASIMBA_LDAP_CONFIGURATION_FILENAME + "'. The environment variable catalina.home isn't defined");
            return null;
        }

        String confPath = System.getProperty("catalina.home") + File.separator + "conf" + File.separator + ASIMBA_LDAP_CONFIGURATION_FILENAME;
        log.info("Reading configuration from: " + confPath);

        return confPath;
    }
    
    public static Properties getLDAPConfigurationProperties() throws OAException {
        String path = getLDAPConfigurationFilePath();
        
        if (path == null) {
            log.error("Failed to load configuration. path == null");
            return null;
        }
        try (FileInputStream input = new FileInputStream(path)) {
            Properties result = new Properties();
            result.load(input);
            return result;
        } catch (IOException e) {
            log.error("Failed to load configuration from path: " + path, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
    }
    
    public static LdapEntryManager getLDAPEntryManager() throws OAException {
        final LDAPConnectionProvider provider;
        final OperationsFacade ops;
        
        // connect
        try {
            Properties props = LDAPUtility.getLDAPConfigurationProperties();
            provider = new LDAPConnectionProvider(props);
            ops = new OperationsFacade(provider, null);
            return new LdapEntryManager(ops);
        } catch (Exception e) {
            log.error("cannot open LdapEntryManager", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
    }
    
    private static LdapEntryManager getLDAPEntryManagerSafe() {
        try {
            return getLDAPEntryManager();
        } catch (Exception e) {
            log.error(e);
            return null;
        }
    }
    
    public static LdapConfigurationEntry loadAsimbaConfiguration() {
        String applianceDn = getDnForAppliance();
        LdapConfigurationEntry ldapConfiguration = ldapEntryManager.find(LdapConfigurationEntry.class, "ou=oxasimba,ou=configuration,"+applianceDn, null);
        
        return ldapConfiguration;
    }
    
    public static List<IDPEntry> loadIDPs() {
        List<IDPEntry> result = new ArrayList<>();
        try {
            List<LdapIDPEntry> entries = ldapEntryManager.findEntries(getDnForLdapIDPEntry(null), LdapIDPEntry.class, null);

            for (LdapIDPEntry entry : entries) {
                result.add(entry.getEntry());
            }
        } catch (Exception ex) {
            log.error("Failed to load LDAP configuration IDPEntry list");
        }
        return result;
    }
    
    public static List<RequestorPoolEntry> loadRequestorPools() {
        List<RequestorPoolEntry> result = new ArrayList<>();
        try {
            List<LDAPRequestorPoolEntry> entries = ldapEntryManager.findEntries(getDnForLDAPRequestorPoolEntry(null), 
                    LDAPRequestorPoolEntry.class, null);
            for (LDAPRequestorPoolEntry entry : entries) {
                result.add(entry.getEntry());
            }
        } catch (Exception ex) {
            log.error("Failed to load LDAP configuration RequestorPoolEntry list");
        }
        return result;
    }
    
    public static List<RequestorEntry> loadRequestors() {
        List<RequestorEntry> result = new ArrayList<>();
        try {
            List<LDAPRequestorEntry> entries = ldapEntryManager.findEntries(getDnForLDAPRequestorEntry(null),
                    LDAPRequestorEntry.class, null);
            for (LDAPRequestorEntry entry : entries) {
                result.add(entry.getEntry());
            }
        } catch (Exception ex) {
            log.error("Failed to load LDAP configuration RequestorEntry list");
        }
        return result;
    }
    
    public static List<ApplicationSelectorEntry> loadSelectors() {
        List<ApplicationSelectorEntry> result = new ArrayList<>();
        try {
            List<LDAPApplicationSelectorEntry> entries = ldapEntryManager.findEntries(getDnForLDAPApplicationSelectorEntry(null),
                    LDAPApplicationSelectorEntry.class, null);
            for (LDAPApplicationSelectorEntry entry : entries) {
                result.add(entry.getEntry());
            }
        } catch (Exception ex) {
            log.error("Failed to load LDAP configuration ApplicationSelectorEntry list");
        }
        return result;
    }
    
    public static List<RequestorEntry> loadRequestorsForPool(String poolID) {
        List<RequestorEntry> result = new ArrayList<>();
        try {
            List<LDAPRequestorEntry> entries = ldapEntryManager.findEntries(getDnForLDAPRequestorEntry(null),
                    LDAPRequestorEntry.class, null);
            for (LDAPRequestorEntry entry : entries) {
                if (poolID.equalsIgnoreCase(entry.getId())) {
                    result.add(entry.getEntry());
                }
            }
        } catch (Exception ex) {
            log.error("Failed to load LDAP configuration RequestorEntry list");
        }
        return result;
    }
    
    /**
    * Build DN string for LdapIDPEntry
    * 
    * @param inum entry Inum
    * @return DN string for specified entry or DN for entry branch if inum is null
    * @throws Exception
    */
    public static String getDnForLdapIDPEntry(String inum) {
        String applianceDn = getDnForAppliance();
        if (StringHelper.isEmpty(inum)) {
                return String.format("ou=idps,ou=oxasimba,ou=configuration,%s", applianceDn);
        }
        return String.format("inum=%s,ou=idps,ou=oxasimba,ou=configuration,%s", inum, applianceDn);
    }
    
    /**
    * Build DN string for LDAPApplicationSelectorEntry
    * 
    * @param inum entry Inum
    * @return DN string for specified entry or DN for entry branch if inum is null
    * @throws Exception
    */
    public static String getDnForLDAPApplicationSelectorEntry(String inum) {
        String applianceDn = getDnForAppliance();
        if (StringHelper.isEmpty(inum)) {
                return String.format("ou=selectors,ou=oxasimba,ou=configuration,%s", applianceDn);
        }
        return String.format("inum=%s,ou=selectors,ou=oxasimba,ou=configuration,%s", inum, applianceDn);
    }
    
    /**
    * Build DN string for LDAPRequestorEntry
    * 
    * @param inum entry Inum
    * @return DN string for specified entry or DN for entry branch if inum is null
    * @throws Exception
    */
    public static String getDnForLDAPRequestorEntry(String inum) {
        String applianceDn = getDnForAppliance();
        if (StringHelper.isEmpty(inum)) {
                return String.format("ou=requestors,ou=oxasimba,ou=configuration,%s", applianceDn);
        }
        return String.format("inum=%s,ou=requestors,ou=oxasimba,ou=configuration,%s", inum, applianceDn);
    }
    
    /**
    * Build DN string for LDAPRequestorPoolEntry
    * 
    * @param inum entry Inum
    * @return DN string for specified entry or DN for entry branch if inum is null
    * @throws Exception
    */
    public static String getDnForLDAPRequestorPoolEntry(String inum) {
        String applianceDn = getDnForAppliance();
        if (StringHelper.isEmpty(inum)) {
                return String.format("ou=requestorpools,ou=oxasimba,ou=configuration,%s", applianceDn);
        }
        return String.format("inum=%s,ou=requestorpools,ou=oxasimba,ou=configuration,%s", inum, applianceDn);
    }
    
    public static String getDnForAppliance() {
        //TODO:
        return "TODO";
    }
    

}
