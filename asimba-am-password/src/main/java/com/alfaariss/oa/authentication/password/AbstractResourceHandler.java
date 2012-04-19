/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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
package com.alfaariss.oa.authentication.password;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Abstract Resource Handler.
 * 
 * @author BNE
 * @author Alfa & Ariss
 * @since 1.0
 */
public abstract class AbstractResourceHandler implements IResourceHandler
{
    private final Log _logger;

    /**
     * _sResourceRealm
     */
    protected String _sResourceRealm;

    /**
     * FullUid
     */
    protected boolean _bFullUid;
    
    /**
     * Configuration manager 
     */
    protected IConfigurationManager _configurationManager;

    /**
     * Constructor
     */
    public AbstractResourceHandler ()
    {
        _logger = LogFactory.getLog(this.getClass());
    }

    /**
     * @see IResourceHandler#init(com.alfaariss.oa.api.configuration.IConfigurationManager,
     *      org.w3c.dom.Element)
     */
    public void init(IConfigurationManager cm, Element eResourceSection)
        throws OAException
    {
        _configurationManager = cm;
        // Get realm
        _sResourceRealm = cm.getParam(eResourceSection, "realm");
        if (_sResourceRealm == null)
        {
            _sResourceRealm = "";
            _logger.warn("No optional 'realm' parameter found in resource configuration");
        }
        else
        {
            if (_sResourceRealm.equals(""))
            {
                _logger.error("Empty realm found");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
    
            // check if realm is valid
            if (!_sResourceRealm.startsWith("@"))
            {
                _logger.error("Invalid realm found (must start with '@'): " + _sResourceRealm);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        
        _bFullUid = false;

        // Get full_uid
        String sFullUid = cm.getParam(eResourceSection, "full_uid");
        if ((sFullUid == null) || sFullUid.equalsIgnoreCase("false"))
        {
            StringBuffer sb = new StringBuffer("Full uid disabled for realm '");
            sb.append(_sResourceRealm);
            sb.append("' using default: full_uid = ");
            sb.append(_bFullUid);
            _logger.info(sb.toString());
        }
        else if (sFullUid.equalsIgnoreCase("true"))
        {
            _bFullUid = true;
            _logger.info("Using full UID");
        }
        else
        {
            StringBuffer sb = new StringBuffer(
            "Invalid 'full_uid' defined for realm '");
            sb.append(_sResourceRealm);
            sb.append("': ");
            sb.append(sFullUid);
            _logger.error(sb.toString());
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
    }
    
    /**
     * @return the _sResourceRealm
     */
    public String getResourceRealm()
    {
        return _sResourceRealm;
    }

    /**
     * Create the correct username (based on using fullid)
     * 
     * @param s
     *            The string to create from.
     * @return The username.
     */
    protected String constructUsername(String s)
    {
        String sReturn = s;
        if (!_bFullUid)
        {
            if (sReturn.toLowerCase().endsWith(_sResourceRealm.toLowerCase()))
                sReturn = sReturn.substring(0, sReturn.length() - _sResourceRealm.length());
        }
        
        return sReturn;
    }
}
