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
import com.unboundid.ldap.sdk.Filter;
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
import org.xdi.config.oxtrust.LdapOxAsimbaConfiguration;
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
    
    @Deprecated
    private static final String ASIMBA_LDAP_CONFIGURATION_FILENAME = "oxasimba-ldap.properties";
    
    private static final String OX_LDAP_CONFIGURATION_FILENAME = "ox-ldap.properties";
    
    @Deprecated
    private static final String CONFIGURATION_ENTRY_DN = "configurationEntryDN";
    
    private static final String OXASIMBA_CONFIGURATION_ENTRY_DN = "oxasimba_ConfigurationEntryDN";
    
    private static final String SALT_FILE_NAME = "salt";
    
    /**
     * oxAsimba LDAP fields
     */
    public static final String inum = "inum";
    public static final String iname = "iname";
    public static final String uniqueIdentifier = "uniqueIdentifier";
    public static final String friendlyName = "friendlyName";
    public static final String identificationURL = "identificationURL";
    public static final String organizationId = "organizationId";
    public static final String description = "description";
    
    private static final LdapEntryManager ldapEntryManager = getLDAPEntryManagerSafe();
    
    private static String configurationEntryDN;
    
    public static String getBaseDirectory() {
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
        String configurationFilePath = getBaseDirectory() + File.separator + "conf" + File.separator + ASIMBA_LDAP_CONFIGURATION_FILENAME;
        // check availability
        File configurationFile = new File(configurationFilePath);
        if (!configurationFile.exists() || !configurationFile.isFile() || !configurationFile.canRead()) {
            // read common configuration in ox-ldap.properties
            configurationFilePath = getBaseDirectory() + File.separator + "conf" + File.separator + OX_LDAP_CONFIGURATION_FILENAME;
        }
        
        return configurationFilePath;
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
    
    public static synchronized LdapEntryManager getLDAPEntryManager() throws OAException {
        // connect
        try {
            FileConfiguration configuration = createFileConfiguration(getConfigurationFilePath(), false);
            
            configurationEntryDN = configuration.getString(OXASIMBA_CONFIGURATION_ENTRY_DN);
            
            if (configurationEntryDN == null || "".equals(configurationEntryDN))
                configurationEntryDN = configuration.getString(CONFIGURATION_ENTRY_DN);
            
            final String cryptoConfigurationSalt = loadCryptoConfigurationSalt();
            
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
            return getLDAPEntryManager();
        } catch (Exception e) {
            log.error(e);
            return null;
        }
    }
    
    public static synchronized LdapOxAsimbaConfiguration loadAsimbaConfiguration() {
        String applianceDn = getDnForAsimbaAppliance();
        LdapOxAsimbaConfiguration ldapConfiguration = ldapEntryManager.find(LdapOxAsimbaConfiguration.class, applianceDn, null);
        
        return ldapConfiguration;
    }
    
    public static synchronized List<IDPEntry> loadIDPs() {
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
    
    public static synchronized List<RequestorPoolEntry> loadRequestorPools() {
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
    
    public static synchronized List<RequestorEntry> loadRequestors() {
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
    
    public static synchronized List<ApplicationSelectorEntry> loadSelectors() {
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
    
    public static synchronized List<RequestorEntry> loadRequestorsForPool(String poolID) {
        List<RequestorEntry> result = new ArrayList<>();
        try {
            List<LDAPRequestorEntry> entries = ldapEntryManager.findEntries(getDnForLDAPRequestorEntry(null),
                    LDAPRequestorEntry.class, null);
            for (LDAPRequestorEntry entry : entries) {
                if (poolID.equalsIgnoreCase(entry.getEntry().getPoolID())) {
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
        String asimbaDn = getDnForAsimbaData();
        if (StringHelper.isEmpty(inum)) {
                return String.format("ou=idps,%s", asimbaDn);
        }
        return String.format("inum=%s,ou=idps,%s", inum, asimbaDn);
    }
    
    /**
    * Build DN string for LDAPApplicationSelectorEntry
    * 
    * @param inum entry Inum
    * @return DN string for specified entry or DN for entry branch if inum is null
    * @throws Exception
    */
    public static String getDnForLDAPApplicationSelectorEntry(String inum) {
        String asimbaDn = getDnForAsimbaData();
        if (StringHelper.isEmpty(inum)) {
                return String.format("ou=selectors,%s", asimbaDn);
        }
        return String.format("inum=%s,ou=selectors,%s", inum, asimbaDn);
    }
    
    /**
    * Build DN string for LDAPRequestorEntry
    * 
    * @param inum entry Inum
    * @return DN string for specified entry or DN for entry branch if inum is null
    * @throws Exception
    */
    public static String getDnForLDAPRequestorEntry(String inum) {
        String applianceDn = getDnForAsimbaData();
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
        String asimbaDn = getDnForAsimbaData();
        if (StringHelper.isEmpty(inum)) {
                return String.format("ou=requestorpools,%s", asimbaDn);
        }
        return String.format("inum=%s,ou=requestorpools,%s", inum, asimbaDn);
    }
    
    public static String getDnForAsimbaAppliance() {
        return configurationEntryDN;
    }
    
    public static String getDnForAsimbaData() {
        try {
            LdapOxAsimbaConfiguration configuration = loadAsimbaConfiguration();
            String asimbaDn = configuration.getApplicationConfiguration().getOxasimba();
            log.info("oxasimba: " + asimbaDn);
            return asimbaDn;
        } catch (Exception e) {
            log.error("Failed to load AsimbaConfiguration from LDAP Appliance", e);
            return null;
        }
    }
    
    /**
    * Search by pattern
    * 
    * @param pattern Pattern
    * @param sizeLimit Maximum count of results
    * @return List of scopes
    * @throws Exception
    */
    public List<IDPEntry> searchIDPs(String pattern, int sizeLimit) throws Exception {
        // filter
        String[] targetArray = new String[] { pattern };
        Filter idFilter = Filter.createSubstringFilter(uniqueIdentifier, null, targetArray, null);
        Filter friendlyNameFilter = Filter.createSubstringFilter(friendlyName, null, targetArray, null);
        Filter descriptionFilter = Filter.createSubstringFilter(description, null, targetArray, null);
        Filter inameFilter = Filter.createSubstringFilter(iname, null, targetArray, null);
        Filter searchFilter = Filter.createORFilter(idFilter, friendlyNameFilter, descriptionFilter, inameFilter);

        // search
        final List<LdapIDPEntry> entries = ldapEntryManager.findEntries(getDnForLdapIDPEntry(null), LdapIDPEntry.class, searchFilter, sizeLimit);

        // convert result
        List<IDPEntry> ret = new ArrayList<IDPEntry>();
        for (LdapIDPEntry entry : entries) {
            ret.add(entry.getEntry());
        }
        return ret;
    }
    
    /**
    * Search by pattern
    * 
    * @param pattern Pattern
    * @param sizeLimit Maximum count of results
    * @return List of scopes
    * @throws Exception
    */
    public List<ApplicationSelectorEntry> searchSelectors(String pattern, int sizeLimit) throws Exception {
        // filter
        String[] targetArray = new String[] { pattern };
        Filter idFilter = Filter.createSubstringFilter(uniqueIdentifier, null, targetArray, null);
        Filter friendlyNameFilter = Filter.createSubstringFilter(friendlyName, null, targetArray, null);
        Filter descriptionFilter = Filter.createSubstringFilter(description, null, targetArray, null);
        Filter inameFilter = Filter.createSubstringFilter(iname, null, targetArray, null);
        Filter organizationIdFilter = Filter.createSubstringFilter(organizationId, null, targetArray, null);
        Filter searchFilter = Filter.createORFilter(idFilter, friendlyNameFilter, descriptionFilter, inameFilter, organizationIdFilter);

        // search
        List<LDAPApplicationSelectorEntry> entries = ldapEntryManager.findEntries(getDnForLDAPApplicationSelectorEntry(null), LDAPApplicationSelectorEntry.class, searchFilter, sizeLimit);

        // convert result
        List<ApplicationSelectorEntry> ret = new ArrayList<ApplicationSelectorEntry>();
        for (LDAPApplicationSelectorEntry entry : entries) {
            ret.add(entry.getEntry());
        }
        return ret;
    }
    
    /**
    * Search by pattern
    * 
    * @param pattern Pattern
    * @param sizeLimit Maximum count of results
    * @return List of scopes
    * @throws Exception
    */
    public List<RequestorEntry> searchRequestors(String pattern, int sizeLimit) throws Exception {
        // filter
        String[] targetArray = new String[] { pattern };
        Filter idFilter = Filter.createSubstringFilter(uniqueIdentifier, null, targetArray, null);
        Filter friendlyNameFilter = Filter.createSubstringFilter(friendlyName, null, targetArray, null);
        Filter descriptionFilter = Filter.createSubstringFilter(description, null, targetArray, null);
        Filter inameFilter = Filter.createSubstringFilter(iname, null, targetArray, null);
        Filter searchFilter = Filter.createORFilter(idFilter, friendlyNameFilter, descriptionFilter, inameFilter);

        // search
        List<LDAPRequestorEntry> entries = ldapEntryManager.findEntries(getDnForLDAPRequestorEntry(null), LDAPRequestorEntry.class, searchFilter, sizeLimit);

        // convert result
        List<RequestorEntry> ret = new ArrayList<RequestorEntry>();
        for (LDAPRequestorEntry entry : entries) {
            ret.add(entry.getEntry());
        }
        return ret;
    }
    
    /**
    * Search by pattern
    * 
    * @param pattern Pattern
    * @param sizeLimit Maximum count of results
    * @return List of scopes
    * @throws Exception
    */
    public List<RequestorPoolEntry> searchRequestorPools(String pattern, int sizeLimit) throws Exception {
        // filter
        String[] targetArray = new String[] { pattern };
        Filter idFilter = Filter.createSubstringFilter(uniqueIdentifier, null, targetArray, null);
        Filter friendlyNameFilter = Filter.createSubstringFilter(friendlyName, null, targetArray, null);
        Filter descriptionFilter = Filter.createSubstringFilter(description, null, targetArray, null);
        Filter inameFilter = Filter.createSubstringFilter(iname, null, targetArray, null);
        Filter searchFilter = Filter.createORFilter(idFilter, friendlyNameFilter, descriptionFilter, inameFilter);

        // search
        List<LDAPRequestorPoolEntry> entries = ldapEntryManager.findEntries(getDnForLDAPRequestorPoolEntry(null), LDAPRequestorPoolEntry.class, searchFilter, sizeLimit);

        // convert result
        List<RequestorPoolEntry> ret = new ArrayList<RequestorPoolEntry>();
        for (LDAPRequestorPoolEntry entry : entries) {
            ret.add(entry.getEntry());
        }
        return ret;
    }
    
}