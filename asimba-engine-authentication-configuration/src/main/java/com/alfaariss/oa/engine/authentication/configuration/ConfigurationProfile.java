/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
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
 * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
 */
package com.alfaariss.oa.engine.authentication.configuration;

import java.util.Properties;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.authentication.IAuthenticationMethod;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.authentication.AuthenticationException;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;

/**
 * Creates the authentication method based on configuration items.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ConfigurationProfile extends AuthenticationProfile
{
    private static final long serialVersionUID = 9142656710779277563L;
    private static Log _logger;
    
    /**
     * Creates a profile object.
     *
     * Creates the profile object by reading the required information from the 
     * configuration file.
     * @param oConfigurationManager The configuration manager where the 
     * configuration can be read from.
     * @param eConfig the configuration section with the configuration needed 
     * for this method.
     * @throws AuthenticationException
     */
    public ConfigurationProfile(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws AuthenticationException
    {
        super();
        try
        {
            _logger = LogFactory.getLog(ConfigurationProfile.class);

            _sID = oConfigurationManager.getParam(eConfig, "id");
            if (_sID == null)
            {
                _logger.error("No 'id' item in 'profile' section found in configuration");
                throw new AuthenticationException(SystemErrors.ERROR_CONFIG_READ);
            }
            _sFriendlyName = oConfigurationManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null)
            {
                _logger.error("No 'friendlyname' item in 'profile' section found in configuration");
                throw new AuthenticationException(SystemErrors.ERROR_CONFIG_READ);
            }       
            _bEnabled = true;
            String sEnabled = oConfigurationManager.getParam(eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " 
                        + sEnabled);
                    throw new AuthenticationException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            Element eProperties = oConfigurationManager.getSection(
                eConfig, "properties");
            
            if (eProperties == null)
            {
                _logger.info(
                    "No 'properties' section found, no extended properties found for authentication profile: " 
                    + _sID);
                _properties = new Properties();
            }
            else
            {
                _properties = readExtendedProperties(
                    oConfigurationManager, eProperties);
            }   
            
            _listAuthenticationMethods = new Vector<IAuthenticationMethod>();
            
            Element eMethod = oConfigurationManager.getSection(eConfig, "method");
            if(eMethod == null)
            {
                _logger.error("No methods found in authn profile: " + _sID);
                throw new AuthenticationException(SystemErrors.ERROR_CONFIG_READ);
            }
            while (eMethod != null)
            {
                ConfigurationMethod method = new ConfigurationMethod(oConfigurationManager, eMethod);
                if (_listAuthenticationMethods.contains(method))
                {
                    StringBuffer sbError = new StringBuffer("Configured authn method '");
                    sbError.append(method.getID());
                    sbError.append("' is not unique in authn profile: ");
                    sbError.append(_sID);
                    _logger.error(sbError.toString());
                    throw new AuthenticationException(SystemErrors.ERROR_CONFIG_READ);
                }

                _listAuthenticationMethods.add(method);
                eMethod = oConfigurationManager.getNextSection(eMethod);
            }
        }
        catch (AuthenticationException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new AuthenticationException(SystemErrors.ERROR_INTERNAL);
        }
    }

    //Read extended properties form configuration
    private Properties readExtendedProperties(
        IConfigurationManager config, Element eProperties) throws OAException
    {
        Properties prop = new Properties();
        Element eProperty = config.getSection(eProperties, "property");
        while(eProperty != null)
        {
            String sName = config.getParam(eProperty, "name");
            if (sName == null)
            {
                _logger.error(
                    "No 'name' item found in 'property' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            if(prop.containsKey(sName))
            {
                _logger.error(
                    "Duplicate 'name' item found in 'property' section in configuration, property is not added: " + sName);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sValue = config.getParam(eProperty, "value");
            if (sValue == null)
            {
                _logger.error(
                    "No 'value' item found in 'property' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            prop.put(sName, sValue);
            eProperty = config.getNextSection(eProperty);
        }
        return prop;
    }
}
