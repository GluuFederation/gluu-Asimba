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
package com.alfaariss.oa.engine.requestor.configuration;

import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.requestor.Requestor;
import com.alfaariss.oa.engine.core.requestor.RequestorException;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;

/**
 * Requestor pool factory.
 * 
 * Reads the information from the configuration.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ConfigurationPool extends RequestorPool
{   
    private static Log _logger;
    
    /**
     * Creates the object.
     *  
     * @param oConfigurationManager The configuration manager where the config 
     * can be read from.
     * @param eConfig The configuration base section.
     * @throws RequestorException
     */
    public ConfigurationPool(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws RequestorException
    {
        try
        {
            _logger = LogFactory.getLog(ConfigurationPool.class);
            
            _sID = oConfigurationManager.getParam(eConfig, "id");
            if (_sID == null)
            {
                _logger.error("No 'id' item in 'pool' section found in configuration");
                throw new RequestorException(SystemErrors.ERROR_CONFIG_READ);
            }
            _sFriendlyName = oConfigurationManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null)
            {
                _logger.error("No 'friendlyname' item in 'pool' section found in configuration");
                throw new RequestorException(SystemErrors.ERROR_CONFIG_READ);
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
                    throw new RequestorException(SystemErrors.ERROR_CONFIG_READ);
                }
            }

            readPoolConfiguration(oConfigurationManager, eConfig);
        }
        catch (RequestorException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during pool object creation", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
    }

    private void readPoolConfiguration(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws RequestorException
    {
        try
        {
            Element eAuthorization = oConfigurationManager.getSection(eConfig, "authorization");
            if (eAuthorization != null)
            {
                Element ePre = oConfigurationManager.getSection(eAuthorization, "pre");
                if (ePre != null)
                    _sPreAuthorizationProfileID = oConfigurationManager.getParam(ePre, "profile");
                Element ePost = oConfigurationManager.getSection(eAuthorization, "post");
                if (ePost != null)
                    _sPostAuthorizationProfileID = oConfigurationManager.getParam(ePost, "profile");
            }
            Element eAttributeRelease = oConfigurationManager.getSection(eConfig, "attributerelease");
            if (eAttributeRelease != null)
                _sAttributeReleasePolicyID = oConfigurationManager.getParam(eAttributeRelease, "policy");
            
            Element eAuthentication = oConfigurationManager.getSection(eConfig, "authentication");
            if (eAuthentication != null)
            {
                _bForced = false;
                String sForced = oConfigurationManager.getParam(eAuthentication, "forced");
                if (sForced != null)
                {
                    if (sForced.equalsIgnoreCase("TRUE"))
                        _bForced = true;
                    else if (!sForced.equalsIgnoreCase("FALSE"))
                    {
                        StringBuffer sbError = new StringBuffer("Wrong configuration in requestor pool with id '");
                        sbError.append(_sID);
                        sbError.append("': Unknown value in 'forced' configuration item: ");
                        sbError.append(sForced);
                        
                        _logger.error(sbError.toString());
                        throw new RequestorException(SystemErrors.ERROR_CONFIG_READ);
                    }
                }
                
                Element eAuthProfile = oConfigurationManager.getSection(eAuthentication, "profile");
                while (eAuthProfile != null)
                {
                    addAuthenticationProfileID(oConfigurationManager.getParam(eAuthProfile, "id"));
                    eAuthProfile = oConfigurationManager.getNextSection(eAuthProfile);
                }
            }
            
            Element eProperties = oConfigurationManager.getSection(
                eConfig, "properties");

            if (eProperties == null)
            {
                _logger.info(
                    "No 'properties' section found, no extended properties found for requestorpool: " 
                    + _sID);
                _properties = new Properties();
            }
            else
            {
                _properties = readExtendedProperties(
                    oConfigurationManager, eProperties);
            }
            
            Element eRequestors = oConfigurationManager.getSection(eConfig, "requestors");
            if (eRequestors == null)
            {
                _logger.error("No 'requestors' section found");
                throw new RequestorException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eRequestor = oConfigurationManager.getSection(eRequestors, "requestor");
            while(eRequestor != null)
            {
                Requestor oRequestor = createRequestor(oConfigurationManager, eRequestor);
                if (oRequestor != null)
                    addRequestor(oRequestor);
                
                eRequestor = oConfigurationManager.getNextSection(eRequestor);
            }
        }
        catch (RequestorException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during pool object update", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private Requestor createRequestor(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws RequestorException
    {
        Requestor oRequestor = null;
        try
        {
            String sID = oConfigurationManager.getParam(eConfig, "id");
            if (sID == null)
            {
                _logger.error("No 'id' item in 'requestor' section found in configuration");
                throw new RequestorException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sEnabled = oConfigurationManager.getParam(eConfig, "enabled");
            boolean bEnabled = true;
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " 
                        + sEnabled);
                    throw new RequestorException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            if (!bEnabled)
            {
                StringBuffer sbInfo = new StringBuffer("Requestor with id '");
                sbInfo.append(sID);
                sbInfo.append("' is disabled");
                _logger.info(sbInfo.toString());
                return null;
            }
            
            String sFriendlyName = oConfigurationManager.getParam(eConfig, "friendlyname");
            if (sFriendlyName == null)
            {
                _logger.error("No 'friendlyname' item in 'requestor' section found in configuration");
                throw new RequestorException(SystemErrors.ERROR_CONFIG_READ);
            }                                             
            
            Element eProperties = oConfigurationManager.getSection(
                eConfig, "properties");
            Properties properties = null;
            if (eProperties == null)
            {
                _logger.info(
                    "No 'properties' section found, no extended properties found for requestor: " 
                    + sID);
                properties = new Properties();
            }
            else
            {
                properties = readExtendedProperties(
                    oConfigurationManager, eProperties);
            }            
                     
            oRequestor = new Requestor(sID, sFriendlyName, bEnabled, properties);
            _logger.info("Found: " + oRequestor);
        }
        catch (RequestorException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during pool object update", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL, e);
        }
        
        return oRequestor;
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
