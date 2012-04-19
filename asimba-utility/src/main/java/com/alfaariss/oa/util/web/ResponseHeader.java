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
package com.alfaariss.oa.util.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Class that stores response headers.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.1
 */
public class ResponseHeader
{
    private Log _logger;
    private String _sName;
    private String _sValue;
    
    /**
     * Constructor.
     * @param configurationManager The configuration manager.
     * @param config The header configuration.
     * @throws OAException if configuration is invalid. 
     */
    public ResponseHeader(IConfigurationManager configurationManager, 
        Element config) throws OAException
    {
        _logger = LogFactory.getLog(ResponseHeader.class);
        try
        {
            _sName = configurationManager.getParam(config, "name");
            if (_sName == null)
            {
                _logger.error("No 'name' item found in 'header' section in configuration");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            _sValue = configurationManager.getParam(config, "value");
            if (_sValue == null)
            {
                _logger.error("No 'value' item found in 'header' section in configuration");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Returns the name of the header.
     * 
     * @return The name of the header
     */
    public String getName()
    {
        return _sName;
    }
    
    /**
     * Returns the value of the header.
     * 
     * @return The value of the header
     */
    public String getValue()
    {
        return _sValue;
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        return _sName + " - " + _sValue;
    }
}
