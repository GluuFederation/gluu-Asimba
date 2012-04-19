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
package com.alfaariss.oa.engine.authentication.configuration;
import java.util.HashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.authentication.AuthenticationException;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;
import com.alfaariss.oa.engine.core.authentication.factory.IAuthenticationProfileFactory;

/**
 * The authentication profile factory.
 *
 * Reads factory information from configuration items.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ConfigurationFactory implements IAuthenticationProfileFactory, 
    IComponent 
{
    private static Log _logger;
    private IConfigurationManager _configurationManager;
    private HashMap<String, AuthenticationProfile> _mapAuthenticationProfiles;
    
    /**
     * Creates the object. 
     */
	public ConfigurationFactory()
    {
        _logger = LogFactory.getLog(ConfigurationFactory.class);
        _mapAuthenticationProfiles = new HashMap<String, AuthenticationProfile>();
	}

    /**
     * Returns the configured authentication profile identified by the supplied id.
     * @see com.alfaariss.oa.engine.core.authentication.factory.IAuthenticationProfileFactory#getProfile(java.lang.String)
     */
    public AuthenticationProfile getProfile(String sProfile) throws AuthenticationException
    {
        return _mapAuthenticationProfiles.get(sProfile);
    }

    /**
     * Initializes the component.
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws OAException
    {
        try
        {
            _configurationManager = oConfigurationManager;
            Element eProfile = _configurationManager.getSection(eConfig, "profile");
            while (eProfile != null)
            {
                AuthenticationProfile oProfile = new ConfigurationProfile(_configurationManager, eProfile);
                _mapAuthenticationProfiles.put(oProfile.getID(), oProfile);
                eProfile = _configurationManager.getNextSection(eProfile);
            }
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new AuthenticationException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Restarts the component.
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element eConfig) throws OAException
    {
        synchronized (this)
        {
            stop();
            start(_configurationManager, eConfig);
        }
    }

    /**
     * Stops the component.
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public void stop()
    {
        if (_mapAuthenticationProfiles != null)
            _mapAuthenticationProfiles.clear();
    }




}