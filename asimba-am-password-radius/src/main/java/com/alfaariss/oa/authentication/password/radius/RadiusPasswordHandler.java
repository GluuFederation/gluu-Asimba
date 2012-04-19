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
package com.alfaariss.oa.authentication.password.radius;

import net.jradius.client.RadiusClient;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.AbstractPasswordHandler;
import com.alfaariss.oa.authentication.password.IPasswordHandler;

/**
 * Password Handler for RADIUS Authentication.
 *
 * Password Handler for RADIUS Authentication using JRadius client library.
 * @author LVR
 * @author Alfa & Ariss
 *
 */
public class RadiusPasswordHandler extends AbstractPasswordHandler
{
    private final Log _logger;
    RadiusClient _radiusClient = null;

    /**
     * Default constructor of <code>RadiusPasswordHandler</code>.
     */
    public RadiusPasswordHandler()
    {
        _logger = LogFactory.getLog(RadiusPasswordHandler.class);
    }

    /**
     * @see IPasswordHandler#start(IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager _configurationManager, Element eConfig) throws OAException
    {
        super.start(_configurationManager, eConfig);
        int iServerRetries = 0;

        try
        {
            //get RADIUS number of allowed retries.
            String sServerRetries = _configurationManager.getParam(eConfig, "server_retries");
            if((sServerRetries == null) || sServerRetries.trim().equals(""))
            {
                _logger.warn("No (optional) 'server_retries' found in RADIUS 'handler' section");
            }
            else
            {
                try
                {
                    iServerRetries  = Integer.parseInt(sServerRetries);
                }
                catch(NumberFormatException e)
                {
                    _logger.error("Invalid format for parameter 'server_retries'");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }

            Element eResourceConfig  = _configurationManager.getSection(eConfig, "resource");
            if (eResourceConfig == null)
            {
                _logger.error("no radius resource server defined");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            while (eResourceConfig != null)
            {
                RadiusProtocolResource handler = new RadiusProtocolResource();

                handler.init(_configurationManager, eResourceConfig, iServerRetries);
                if ("".equals(handler.getResourceRealm()))
                    setResourceHandler(handler);
                else
                    addResourceHandler(handler);

                eResourceConfig = _configurationManager.getNextSection(eResourceConfig);
            }

            setDefault(_configurationManager, eConfig);
        }
        catch(OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.error("Error initializing Radius password handler", e);
            throw new OAException(SystemErrors.ERROR_INIT);
        }
    }
}
