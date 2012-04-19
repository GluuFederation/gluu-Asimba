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
package com.alfaariss.oa.authentication.password.jdbc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.AbstractPasswordHandler;
import com.alfaariss.oa.authentication.password.IPasswordHandler;
import com.alfaariss.oa.authentication.password.IResourceHandler;

/**
 * Password Handler for JDBC Authentication.
 * 
 * @author JVG
 * @author BNE
 * @author Alfa & Ariss
 *
 */
public class JDBCPasswordHandler extends AbstractPasswordHandler
{
    private final Log _logger;

    /**
     * Default constructor of <code>JDBCPasswordHandler</code>.
     */
    public JDBCPasswordHandler()
    {
        _logger = LogFactory.getLog(JDBCPasswordHandler.class);
    }

    /**
     * @see IPasswordHandler#start(IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager oConfigurationManager, Element eConfig)
    throws OAException
    {
        super.start(oConfigurationManager, eConfig);

        try
        {
            Element eResourceSection = oConfigurationManager.getSection(
                eConfig, "resource");
            if (eResourceSection == null)
            {
                _logger.error("no jdbc resource server defined");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            while (eResourceSection != null)
            {
                IResourceHandler oProtocolHandler;

                oProtocolHandler = createResource();

                oProtocolHandler.init(oConfigurationManager, eResourceSection);
                if ("".equals(oProtocolHandler.getResourceRealm()))
                    setResourceHandler(oProtocolHandler);
                else
                    addResourceHandler(oProtocolHandler);

                //get next protocolResource section
                eResourceSection = oConfigurationManager.getNextSection(
                    eResourceSection);
            }

            setDefault(oConfigurationManager, eConfig);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal(
                "Internal error during start of JDBCPasswordHandler", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
    }

    /**
     * Creates a new resource.
     * 
     * @return The new resource.
     */
    protected IResourceHandler createResource()
    {
        return new JDBCProtocolResource();
    }
}