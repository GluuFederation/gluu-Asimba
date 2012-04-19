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
package com.alfaariss.oa.profile.aselect.processor.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * The A-Select requestor pool object.
 *
 * A bean object containing the configured requestor pool information.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ASelectRequestorPool
{
    private Log _logger;
    private String _sID;
    private int _iAppLevel;
    private boolean _bUidOpaque;
    private String _sUidOpaqueSalt;
    private String _sUidAttribute;
    private boolean _bSigning;
    
    /**
     * Creates the object.
     * 
     * The object can be disabled. This should be checked before the object is 
     * used, because the object won't be fully initialized if it's disabled.
     * The object is disabled if no 'enabled' item is found in the supplied 
     * configuration section or the 'disabled' parameter has the value 'false'.
     * @param oConfigurationManager configuration manager containing the configuration 
     * @param eConfig the configuration section containing the configuration of this object
     * @throws OAException if creation fails
     */
    public ASelectRequestorPool(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException
    {
        try
        {
            _logger = LogFactory.getLog(ASelectRequestorPool.class);
            
            _sID = oConfigurationManager.getParam(eConfig, "id");
            if (_sID == null)
            {
                _logger.warn("No 'id' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            String sLevel = oConfigurationManager.getParam(eConfig, "app_level");
            if (sLevel == null)
            {
                _logger.warn(
                    "No optional 'app_level' parameter found in configuration");
                _iAppLevel = -1;
            }
            else
            {
                try
                {
                    _iAppLevel = Integer.valueOf(sLevel);
                }
                catch (NumberFormatException e)
                {
                    _logger.warn(
                        "The configured 'app_level' parameter isn't a number: " 
                        + sLevel, e);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
            }
            
            _bUidOpaque = false;
            Element eUid = oConfigurationManager.getSection(eConfig, "uid");
            if (eUid != null)
            {
                _sUidAttribute = oConfigurationManager.getParam(
                    eUid, "attribute");
                
                Element eOpaque = oConfigurationManager.getSection(
                    eUid, "opaque");
                if (eOpaque != null)
                {
                    String sUidOpaque = oConfigurationManager.getParam(
                        eOpaque, "enabled");
                    if (sUidOpaque != null)
                    {
                        if (sUidOpaque.equalsIgnoreCase("TRUE"))
                        {
                            _bUidOpaque = true;
                            _sUidOpaqueSalt = oConfigurationManager.getParam(
                                eOpaque, "salt");
                        }
                        else if (!sUidOpaque.equalsIgnoreCase("FALSE"))
                        {
                            _logger.warn(
                                "The configured opaque 'enabled' parameter isn't TRUE or FALSE: " 
                                + sUidOpaque);
                            throw new OAException(SystemErrors.ERROR_INIT);
                        }
                    }
                }
            }
            
            _bSigning = false;
            Element eSigning = oConfigurationManager.getSection(
                eConfig, "signing");
            if (eSigning != null)
            {
                String sEnabled = oConfigurationManager.getParam(
                    eSigning, "enabled");
                if (sEnabled != null)
                {
                    if (sEnabled.equalsIgnoreCase("TRUE"))
                        _bSigning = true;
                    else if (!sEnabled.equalsIgnoreCase("FALSE"))
                    {
                        _logger.warn(
                            "The configured 'enabled' parameter in the 'signing' section isn't TRUE or FALSE: " 
                            + sEnabled);
                        throw new OAException(SystemErrors.ERROR_INIT);
                    }
                }
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during object creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Returns the configured requestor pool id.
     * @return the requestor pool ID
     */
    public String getID()
    {
        return _sID;
    }
    
    /**
     * Returns the configured requestor pool level.
     * @return the requestor pool level
     */
    public int getAppLevel()
    {
        return _iAppLevel;
    }
    
    /**
     * Verifies if responses must contain an opaque user id the requestor pool.
     * @return TRUE if the uid parameter must be an opaque id
     */
    public boolean isUidOpaque()
    {
        return _bUidOpaque;
    }
    
    /**
     * Return the salt that must be used when generating the opaque uid.
     * @return The salt
     */
    public String getUidOpaqueSalt()
    {
        return _sUidOpaqueSalt;
    }
    
    /**
     * Returns the attribute from which the value should be returned as uid. 
     * @return Attribute name
     */
    public String getUidAttribute()
    {
        return _sUidAttribute;
    }
    
    /**
     * Verify if signing is enabled for this requestor pool.
     * @return TRUE if signing is enabled
     */
    public boolean doSigning()
    {
        return _bSigning;
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer sbInfo = new StringBuffer("Requestor (");
        sbInfo.append(_sID).append(") with ");
        sbInfo.append(" app_level=").append(_iAppLevel);
        sbInfo.append(", signing=").append(_bSigning);
        StringBuffer sbUid = new StringBuffer();
        if(_bUidOpaque)
        {
            sbUid.append("opaque");
            if (_sUidOpaqueSalt != null)
                sbUid.append(" with salt '").append(_sUidOpaqueSalt).append("'");
        }
        if (_sUidAttribute != null)
        {
            if (sbUid.length() > 0)
                sbUid.append(",");
            sbUid.append("attribute=").append(_sUidAttribute);
        }
        if (sbUid.length() > 0)
            sbInfo.append(", uid(").append(sbUid).append(")");
        
        return sbInfo.toString();
    }
}
