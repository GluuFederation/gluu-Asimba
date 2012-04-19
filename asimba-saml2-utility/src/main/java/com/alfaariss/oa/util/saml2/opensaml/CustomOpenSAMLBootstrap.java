/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
 * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
 */
package com.alfaariss.oa.util.saml2.opensaml;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;

/**
 * OpenSAML Bootstrap.
 * 
 * Changes the default crypto settings.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.2
 */
public class CustomOpenSAMLBootstrap extends DefaultBootstrap
{
    /** List of default XMLTooling configuration files. */
    private static String[] xmlToolingConfigs = { 
        "/default-config.xml", 
        "/schema-config.xml", 
        "/signature-config.xml",
        "/signature-validation-config.xml", 
        "/encryption-config.xml", 
        "/encryption-validation-config.xml",
        "/soap11-config.xml", 
        "/wsfed11-protocol-config.xml",
        "/saml1-assertion-config.xml", 
        "/saml1-protocol-config.xml",
        "/saml1-core-validation-config.xml", 
        "/saml2-assertion-config.xml", 
        "/saml2-protocol-config.xml",
        "/saml2-core-validation-config.xml", 
        "/saml1-metadata-config.xml", 
        "/saml2-metadata-config.xml",
        "/saml2-metadata-validation-config.xml", 
        "/saml2-metadata-idp-discovery-config.xml",
        "/saml2-protocol-thirdparty-config.xml",
        "/saml2-metadata-query-config.xml", 
        "/saml2-assertion-delegation-restriction-config.xml",    
        "/saml2-ecp-config.xml",
        "/xacml10-saml2-profile-config.xml",
        "/xacml11-saml2-profile-config.xml",
        "/xacml20-context-config.xml",
        "/xacml20-policy-config.xml",
        "/xacml2-saml2-profile-config.xml",
        "/xacml3-saml2-profile-config.xml",    
        "/wsaddressing-config.xml",
        "/wssecurity-config.xml",
    };
    
    /**
     * Initializes the OpenSAML library, loading default configurations.
     * 
     * @throws ConfigurationException thrown if there is a problem initializing the OpenSAML library
     */
    public static synchronized void bootstrap() throws ConfigurationException {

        initializeXMLSecurity();

        initializeVelocity();

        initializeXMLTooling(xmlToolingConfigs);

        initializeArtifactBuilderFactories();

        initializeGlobalSecurityConfiguration();
    }
    
    /**
     * Initializes the default global security configuration.
     */
    protected static void initializeGlobalSecurityConfiguration() 
    {
        Configuration.setGlobalSecurityConfiguration(
            CustomOpenSAMLSecurityConfigurationBootstrap.buildDefaultConfig());
    }
}
