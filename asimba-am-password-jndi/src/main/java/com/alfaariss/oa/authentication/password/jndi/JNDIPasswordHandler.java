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
package com.alfaariss.oa.authentication.password.jndi;

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
 * Password Handler for JNDI Authentication.
 *
 * @author JVG
 * @author Alfa & Ariss
 *
 */
public class JNDIPasswordHandler extends AbstractPasswordHandler
{   
    private final Log _logger;
    
    /**
     * Default constructor of <code>JNDIPasswordHandler</code>.
     */
    public JNDIPasswordHandler()
    {       
        _logger = LogFactory.getLog(JNDIPasswordHandler.class);
    }
    
    /**
     * @see IPasswordHandler#start(IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager configManager, Element eConfig)
    throws OAException
    {
        super.start(configManager, eConfig);

        try
        {
            Element eResourceSection = configManager.getSection(eConfig, "resource");
            if (eResourceSection == null)
            {
                _logger.error("no jndi resource defined");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            while (eResourceSection != null)
            {
                IResourceHandler oProtocolHandler = new JNDIProtocolResource();
                oProtocolHandler.init(configManager, eResourceSection);
                if ("".equals(oProtocolHandler.getResourceRealm()))
                    setResourceHandler(oProtocolHandler);
                else
                    addResourceHandler(oProtocolHandler);
                
                eResourceSection = configManager.getNextSection(eResourceSection);
            }

            setDefault(configManager, eConfig);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during start of JNDIPasswordHandler", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
    }
}