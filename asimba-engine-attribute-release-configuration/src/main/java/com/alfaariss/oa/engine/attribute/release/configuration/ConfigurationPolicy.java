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
package com.alfaariss.oa.engine.attribute.release.configuration;

import java.util.Enumeration;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.attribute.AttributeException;
import com.alfaariss.oa.engine.core.attribute.UserAttributes;
import com.alfaariss.oa.engine.core.attribute.release.IAttributeReleasePolicy;

/**
 * Release policy class.
 *
 * Reads configuration from the configuration document and matches the 
 * attribute names with or without wildcard (*).
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ConfigurationPolicy implements IAttributeReleasePolicy
{
    private static Log _logger;
    private String _sID;
    private String _sFriendlyName;
    private boolean _bEnabled;
    private Vector<String> _vAttributeNames;
    
    /**
     * Initializes the policy.
     *
     * @param oConfigurationManager the configuration manager where the 
     * configuration can be read from
     * @param eConfig the configuration section of this policy
     * @throws AttributeException if initialization fails
     */
    public ConfigurationPolicy(IConfigurationManager 
        oConfigurationManager, Element eConfig) throws AttributeException
    {
        try
        {
            _logger = LogFactory.getLog(ConfigurationPolicy.class);
            _sID = oConfigurationManager.getParam(eConfig, "id");
            if (_sID == null)
            {
                _logger.error("No 'id' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            _sFriendlyName = oConfigurationManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null)
            {
                _logger.error("No 'friendlyname' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            _bEnabled = true;
            String sEnabled = oConfigurationManager.getParam(eConfig, "enabled");
            if (sEnabled != null)
            {
                if(sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if(!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Wrong value for 'enabled' item configured: " + sEnabled);
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            _vAttributeNames = new Vector<String>();
            Element eAttribute = oConfigurationManager.getSection(eConfig, "attribute");
            while (eAttribute != null)
            {
                String sName = oConfigurationManager.getParam(eAttribute, "name");
                if (sName == null)
                {
                    _logger.error("No 'name' item in 'attribute' section configured");
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
                _vAttributeNames.add(sName);
                
                eAttribute = oConfigurationManager.getNextSection(eAttribute);
            }
        }
        catch (AttributeException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Applies the policy to the given attributes.
     * @see com.alfaariss.oa.engine.core.attribute.release.IAttributeReleasePolicy#apply(com.alfaariss.oa.api.attribute.IAttributes)
     */
    public IAttributes apply(IAttributes oAttributes) throws AttributeException
    {
        IAttributes oReturnAttributes = new UserAttributes();
        try
        {
            if (_bEnabled)
            {
                Enumeration enumNames = oAttributes.getNames();
                while (enumNames.hasMoreElements())
                {
                    String sName = (String)enumNames.nextElement();
                    if (matches(sName))
                        oReturnAttributes.put(sName, 
                            oAttributes.getFormat(sName), oAttributes.get(sName));
                }
            }
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during apply of release policy: " + _sID, e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
        return oReturnAttributes;
    }

    /**
     * This policy its unique ID.
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    public String getID()
    {
        return _sID;
    }

    /**
     * This policy its friendly name.
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

    /**
     * Return TRUE if this policy is enabled.
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
    
    /**
     * Matches the supplied attribute name with the policy.
     *
     * Matches agains the configured attribute names or wildcard combination:
     * <ul>
     * <li>*</li>
     * <li>*[matching chars]</li>
     * <li>*[matching chars]*</li>
     * <li>[matching chars]*</li> 
     * <li>exact match</li>
     * </ul>
     * @param sName the name to match the policy
     * @return TRUE if the attribute matches the policy
     */
    private boolean matches(String sName)
    {
        if (_vAttributeNames.contains(sName))
            return true;
            
        for (String sReleaseName: _vAttributeNames)
        {
            int iWildcard = sReleaseName.indexOf("*");
            if (iWildcard == 0)
            {
                String sEnd = sReleaseName.substring(1, sReleaseName.length());
                if (sEnd.length() == 0)//support: *
                    return true;
                else if (sName.endsWith(sEnd))//support: *[name]
                    return true;
                else if (sEnd.endsWith("*"))
                {
                    String sIntermediate = sEnd.substring(0, sEnd.length() - 1);
                    if (sName.contains(sIntermediate))//support: *[name]*
                        return true;
                }
            }  
            else if (iWildcard == sReleaseName.length()-1)
            {
                String sStart = sReleaseName.substring(0, iWildcard);
                if (sName.startsWith(sStart))//support: [name]*
                    return true;
            }
        }
        return false;
    }

}
