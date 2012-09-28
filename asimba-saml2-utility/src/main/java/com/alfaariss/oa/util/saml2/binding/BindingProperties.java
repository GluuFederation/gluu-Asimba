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
package com.alfaariss.oa.util.saml2.binding;

import java.io.Serializable;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.xml.SAMLConstants;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Helper class for reading and buffering binding properties.
 *
 * This class can be initiated at startup to decrease the configuration access 
 * by binding factories.
 *  
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 */
public class BindingProperties implements Serializable
{
    /** serialVersionUID */
    private static final long serialVersionUID = 46260157915151221L;
    /** system logger */
    private static Log _logger = LogFactory.getLog(BindingProperties.class);
    /** The properties */
    private Map<String, Properties> _bindingProperties; 
    private String _sDefault;
    private List<String> _bindings;
    
    /**
     * Constructor. 
     */
    public BindingProperties()
    {
        _bindingProperties = new Hashtable<String, Properties>();
        _bindings = new Vector<String>();
        _sDefault = null;
    }
    
    /**
     * Create new <code>BindingProperties</code> from configuration.
     *
     * @param config The configuration manager.
     * @param eBindings The bindings configuration section.
     * @throws ConfigurationException If reading from configuration fails
     * @throws OAException If configuration is invalid
     */
    public BindingProperties(IConfigurationManager config, 
        Element eBindings) throws OAException
    {
        _bindingProperties = new Hashtable<String, Properties>();
        _bindings = new Vector<String>();
        
        Element eBinding = config.getSection(eBindings, "binding");
        if (eBinding == null)
        {
            _logger.error("Not one 'binding' section found in 'bindings' section in configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _bindingProperties = readBindings(config, eBinding);
        
        //DD added specific check for required path config item for HTTP-POST
        if (isSupported(SAMLConstants.SAML2_POST_BINDING_URI))
        {
            String sPath = getProperty(SAMLConstants.SAML2_POST_BINDING_URI
                    , "path");
            if (sPath == null)
            {
                _logger.error("No 'path' parameter configured for binding: " 
                    + SAMLConstants.SAML2_POST_BINDING_URI);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
        }
        
        //DD added specific check for required path config item for HTTP-Artifact when in `post` mode
        if (isSupported(SAMLConstants.SAML2_ARTIFACT_BINDING_URI))
        {
            if(getBooleanProperty(
                SAMLConstants.SAML2_ARTIFACT_BINDING_URI, "post", false))
            {            
                String sPath = getProperty(SAMLConstants.SAML2_ARTIFACT_BINDING_URI
                        , "path");
                if (sPath == null)
                {
                    _logger.error("No 'path' parameter configured for binding: " 
                        + SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
            }
        }
        
        _sDefault = config.getParam(eBindings, "default");
        if (_sDefault == null)
        {
            _logger.error("No 'default' item found in 'bindings' section in configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        if (!_bindingProperties.keySet().contains(_sDefault))
        {
            _logger.error("Invalid 'default' binding configured: " + _sDefault);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
    }
    
    /**
     * Verifies if binding type is supported.
     * 
     * @param sBindingType The binding type to be checkt.
     * @return TRUE if the binding is supported.
     */
    public boolean isSupported(String sBindingType)
    {
        return _bindingProperties.keySet().contains(sBindingType);
    }
    
    /**
     * Return a property of the given binding.
     * 
     * @param sBindingType The binding URI.
     * @param sName The property name.
     * @return The property value if found, otherwise <code>null</code>.
     * @see SAMLConstants
     */
    public String getProperty(String sBindingType, String sName)
    {
        String sRet = null; 
        Properties prop = _bindingProperties.get(sBindingType);
        if(prop != null)
            sRet = prop.getProperty(sName);     
        return sRet;
    }
    
    /**
     * Return a <code>Boolean</code> property of the given binding.
     * 
     * @param sBindingType The binding URI.
     * @param sName The property name.
     * @return The property value if found, otherwise <code>null</code>.
     * @throws OAException If requested value is not a true or false 
     * @see SAMLConstants
     */
    public Boolean getBooleanProperty(String sBindingType, String sName) 
        throws OAException
    {
        Boolean boolReturn = null;
        String sValue = getProperty(sBindingType, sName);
        
        if (sValue != null)
        {
            boolReturn = Boolean.FALSE;
            if (sValue.equalsIgnoreCase("TRUE"))
                boolReturn = Boolean.TRUE;
            else if (!sValue.equalsIgnoreCase("FALSE"))
            {
                StringBuffer sbError = new StringBuffer("Configured binding '");
                sbError.append(sBindingType);
                sbError.append("' contains a property with name '");
                sbError.append(sName);
                sbError.append("' that has a non Boolean value: ");
                sbError.append(sValue);
                _logger.error(sbError.toString());
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        return boolReturn;
    }
    
    /**
     * Return a <code>Boolean</code> property of the given binding.
     * 
     * @param sBindingType  The binding URI.
     * @param sName The property name.
     * @param bDefault The value that must be returned if property is not available.
     * @return The property value converted to a Boolean object if found, otherwise the supplied default.
     * @throws OAException  If requested value is not a true or false
     * @see SAMLConstants
     */
    public Boolean getBooleanProperty(String sBindingType, String sName, 
        boolean bDefault) throws OAException
    {
        Boolean boolValue = getBooleanProperty(sBindingType, sName);
        if (boolValue == null)
            return new Boolean(bDefault);
        return boolValue;
    }
    
    /**
     * Return a <code>Integer</code> property of the given binding.
     * 
     * @param sBindingType The binding URI.
     * @param sName The property name.
     * @return The property value if found, otherwise <code>null</code>.
     * @throws OAException If requested value is not a number
     * @see SAMLConstants
     */
    public Integer getIntegerProperty(String sBindingType, String sName) 
        throws OAException
    {
        Integer intReturn = null;
        String sValue = getProperty(sBindingType, sName);
        if (sValue != null)
        {   
            try
            {
                intReturn = Integer.valueOf(sValue);
            }
            catch(NumberFormatException e)
            {
                StringBuffer sbError = new StringBuffer("Configured binding '");
                sbError.append(sBindingType);
                sbError.append("' contains a property with name '");
                sbError.append(sName);
                sbError.append("' that has a non Integer value: ");
                sbError.append(sValue);
                _logger.error(sbError.toString(), e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }

        return intReturn;
    }
    
    /**
     * Returns optional configured properties of a binding.
     *
     * Returns a <code>Properties</code> object containing the specifically 
     * configured properties for a binding or an empty <code>Properties</code> 
     * object if no properties configured.
     * 
     * @param sBindingType The binding URI.
     * @return A Properties object containing a the specifically configured properties for a binding or an empty properties object if no configured
     */
    public Properties getProperties(String sBindingType)
    {
        return _bindingProperties.get(sBindingType);
    }
    
    /**
     * Returns an unmodifiable set containing all configured binding types.
     *  
     * @return A <code>List</code> containing all configured binding types.
     */
    public List<String> getBindings()
    {
        return Collections.unmodifiableList(_bindings);
    }
    
    /**
     * Returns the default binding URI.
     * @return The binding URI configured as default
     */
    public String getDefault()
    {
        return _sDefault;
    }
    
    /**
     * Set the supported binding URI's.
     * @param bindings List with all supported binding URI's
     * @since 1.5
     */
    public void setBindings(List<String> bindings)
    {
        _bindings = bindings;
    }
    
    /**
     * Set the default binding URI.
     * @param binding the binding URI
     * @since 1.5
     */
    public void setDefault(String binding)
    {
        _sDefault = binding;
    }
    
    /**
     * Set the binding properties.
     * @param bindingProperties specific binding configuration.
     * @since 1.5
     */
    public void setBindingProperties(Map<String, Properties> bindingProperties)
    {
        _bindingProperties = bindingProperties;
    }
    
    private Map<String, Properties> readBindings(
        IConfigurationManager config, Element eBinding) throws OAException
    {
        Map<String, Properties> bindings = new Hashtable<String, Properties>();
        
        while (eBinding != null)
        {
            String sID = config.getParam(eBinding, "id");
            if (sID == null)
            {
                _logger.error("No 'id' item found in 'binding' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Properties prop = readBindingProperties(config, eBinding);
            
            bindings.put(sID, prop);
            _bindings.add(sID);
            
            eBinding = config.getNextSection(eBinding);
        }
        return bindings;
    }
    
    private Properties readBindingProperties(IConfigurationManager config, 
        Element eBinding) throws OAException
    {
        Properties prop = new Properties();
        
        Element eProperty = config.getSection(eBinding, "property");
        while(eProperty != null)
        {
            String sName = config.getParam(eProperty, "name");
            if (sName == null)
            {
                _logger.error("No 'name' item found in 'property' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sValue = config.getParam(eProperty, "value");
            if (sValue == null)
            {
                _logger.error("No 'value' item found in 'property' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            prop.put(sName, sValue);
            eProperty = config.getNextSection(eProperty);
        }
        
        return prop;
    }
}
