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
import java.util.Properties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * LDAP utility functions.
 * 
 * @author Dmitry Ognyannikov
 */
public class LDAPUtility {
    
    private static final Log log = LogFactory.getLog(LDAPUtility.class);
    
    public static final String LDAP_CONFIGURATION_FILE_NAME = "asimba-ldap.properties";
    
    public static String getLDAPConfigurationFilePath() {
        String tomcatHome = System.getProperty("catalina.home");
        if (tomcatHome == null) {
            log.error("Failed to load configuration from '" + LDAP_CONFIGURATION_FILE_NAME + "'. The environment variable catalina.home isn't defined");
            return null;
        }

        String confPath = System.getProperty("catalina.home") + File.separator + "conf" + File.separator + LDAP_CONFIGURATION_FILE_NAME;
        log.info("Reading configuration from: " + confPath);

        return confPath;
    }
    
    public static Properties getLDAPConfiguration() throws OAException {
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
}
