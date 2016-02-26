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
import org.xdi.model.ldap.GluuLdapConfiguration;
import org.xdi.util.StringHelper;
import org.xdi.util.properties.FileConfiguration;
import org.xdi.util.security.StringEncrypter;

/**
 * LDAP utility functions.
 * 
 * @author Dmitry Ognyannikov
 */
public class LDAPUtility {
    
    private static final Log log = LogFactory.getLog(LDAPUtility.class);
    
    private static final String ASIMBA_LDAP_CONFIGURATION_FILENAME = "oxasimba-ldap.properties";
    
    private static final String SALT_FILE_NAME = "salt";
    
    private static final LdapEntryManager ldapEntryManager = getLDAPEntryManagerSafe();
    
    private static String configurationEntryDN;
    
    private static String getBaseDirectory() {
        if ((System.getProperty("catalina.base") != null) && (System.getProperty("catalina.base.ignore") == null)) {
            return System.getProperty("catalina.base");
        } else if (System.getProperty("catalina.home") != null) {
            return System.getProperty("catalina.home");
        } else if (System.getProperty("jboss.home.dir") != null) {
            return System.getProperty("jboss.home.dir");
        } else {
            return null;
        }
    }
    
    private static String getConfigurationFilePath() {
        return getBaseDirectory() + File.separator + "conf" + File.separator + ASIMBA_LDAP_CONFIGURATION_FILENAME;
    }
    
    private static String getSaltFilePath() {
        return getBaseDirectory() + File.separator + "conf" + File.separator + SALT_FILE_NAME;
    }
    
    private static FileConfiguration createFileConfiguration(String fileName, boolean isMandatory) throws OAException {
        try {
            FileConfiguration fileConfiguration = new FileConfiguration(fileName);
            if (fileConfiguration.isLoaded()) {
                    return fileConfiguration;
            }
        } catch (Exception ex) {
            if (isMandatory) {
                log.error("Failed to load configuration from " + fileName, ex);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }

        return null;
    }
    
    private static String loadCryptoConfigurationSalt() {
        
        try {
            FileConfiguration cryptoConfiguration = createFileConfiguration(getSaltFilePath(), true);

            return cryptoConfiguration.getString("encodeSalt");
        } catch (Exception ex) {
            log.error("Failed to loadCryptoConfigurationSalt() from: " + getSaltFilePath());
            return null;
        }
    }
    
    public static boolean testLdapConnection() {
        try {
            log.info("testLdapConnection(), file path: " + getConfigurationFilePath());
            FileConfiguration configuration = createFileConfiguration(getConfigurationFilePath(), false);
            
            final String dn = configuration.getString("configurationEntryDN");
            log.info("configurationEntryDN: " + dn);
            
            final String cryptoConfigurationSalt = loadCryptoConfigurationSalt();
            
            GluuLdapConfiguration ldapConfig = new GluuLdapConfiguration();
            
            Properties properties = configuration.getProperties();
            properties.setProperty("bindDN", configuration.getString("bindDN"));
            properties.setProperty("bindPassword", StringEncrypter.defaultInstance().decrypt(configuration.getString("bindPassword"), cryptoConfigurationSalt));
            properties.setProperty("servers", configuration.getString("servers"));
            properties.setProperty("useSSL", configuration.getString("useSSL"));
            
            //LDAPConnectionProvider connectionProvider = new LDAPConnectionProvider(PropertiesDecrypter.decryptProperties(properties, cryptoConfigurationSalt));
            LDAPConnectionProvider connectionProvider = new LDAPConnectionProvider(properties);
            if (connectionProvider.isConnected()) {
                log.info("testLdapConnection() result: success");
                connectionProvider.closeConnectionPool();
                return true;
            }
            log.info("testLdapConnection() result: fail");
            connectionProvider.closeConnectionPool();
            return false;

        } catch (Exception ex) {
                log.error("Could not connect to LDAP", ex);
                return false;
        }
    }
    
    public static LdapEntryManager getLDAPEntryManager() throws OAException {
        // connect
        try {
            FileConfiguration configuration = createFileConfiguration(getConfigurationFilePath(), false);
            
            configurationEntryDN = configuration.getString("configurationEntryDN");
            
            final String cryptoConfigurationSalt = loadCryptoConfigurationSalt();
            
            GluuLdapConfiguration ldapConfig = new GluuLdapConfiguration();
            
            Properties properties = configuration.getProperties();
            properties.setProperty("bindDN", configuration.getString("bindDN"));
            properties.setProperty("bindPassword", StringEncrypter.defaultInstance().decrypt(configuration.getString("bindPassword"), cryptoConfigurationSalt));
            properties.setProperty("servers", configuration.getString("servers"));
            properties.setProperty("useSSL", configuration.getString("useSSL"));
            
            final LDAPConnectionProvider provider = new LDAPConnectionProvider(properties);
            final OperationsFacade ops = new OperationsFacade(provider, null);
            return new LdapEntryManager(ops);
        } catch (Exception e) {
            log.error("cannot open LdapEntryManager", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
    }
    
    private static LdapEntryManager getLDAPEntryManagerSafe() {
        try {
            testLdapConnection();
            
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
                return String.format("ou=idps,%s", applianceDn);
        }
        return String.format("inum=%s,ou=idps,%s", inum, applianceDn);
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
                return String.format("ou=selectors,%s", applianceDn);
        }
        return String.format("inum=%s,ou=selectors,%s", inum, applianceDn);
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
                return String.format("ou=requestors,%s", applianceDn);
        }
        return String.format("inum=%s,ou=requestors,%s", inum, applianceDn);
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
                return String.format("ou=requestorpools,%s", applianceDn);
        }
        return String.format("inum=%s,ou=requestorpools,%s", inum, applianceDn);
    }
    
    public static String getDnForAppliance() {
        return configurationEntryDN;
    }
    

}
