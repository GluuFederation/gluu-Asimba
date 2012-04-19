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
package com.alfaariss.oa.engine.core.server;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Creates an object with organization specific items.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class Organization
{
    private static Log _logger;    
    private String _sID;
    private String _sFriendlyName;
    
    /**
     * Creates the object.
     * @param oConfigurationManager the configuration manager where the 
     * configuration can be read from.
     * @param eConfig the configuration section for this object
     * @throws OAException If configuration is invalid
     */
    public Organization (IConfigurationManager oConfigurationManager, Element eConfig) 
        throws OAException
    {
        try
        {
            _logger = LogFactory.getLog(Organization.class);
            
            _sID = oConfigurationManager.getParam(eConfig, "id");
            if (_sID == null || _sID.trim().length() <= 0)
            {
                _logger.error("No 'id' item found in 'organization' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            _sFriendlyName = oConfigurationManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null || _sFriendlyName.trim().length() <= 0)
            {
                _logger.error("No 'friendlyname' item found in 'organization' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        catch(OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialize", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Returns the organization id. 
     * @return the id
     */
    public String getID()
    {
        return _sID;
    }
    
    /**
     * Returns the organization friendly name. 
     * @return the friendly name
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }
    
    /**
     * Returns the organization friendly name.
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        return _sFriendlyName + "(" + _sID + ")";
    }

}
