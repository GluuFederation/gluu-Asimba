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
package com.alfaariss.oa.engine.authorization.configuration;
import java.util.HashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.authorization.AuthorizationException;
import com.alfaariss.oa.engine.core.authorization.AuthorizationProfile;
import com.alfaariss.oa.engine.core.authorization.factory.IAuthorizationFactory;

/**
 * The authorization factory.
 * 
 * Reads factory information from configuration items.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ConfigurationFactory 
    implements IAuthorizationFactory, IComponent 
{
    private static Log _logger;
    private IConfigurationManager _configurationManager;
    
    private boolean _bEnabled;
    private HashMap<String, AuthorizationProfile> _mapProfiles;
    
	/**
	 * Creates the object. 
	 */
	public ConfigurationFactory()
    {
        _logger = LogFactory.getLog(ConfigurationFactory.class);
        _mapProfiles = new HashMap<String, AuthorizationProfile>();
        _bEnabled = true;
	}

	/**
	 * Returns the pre authorization profile or <code>null</code> if it does not 
	 * exist.
	 * 
     * The profile is specified by its ID.
	 * @see com.alfaariss.oa.engine.core.authorization.factory.IAuthorizationFactory#getProfile(java.lang.String)
	 */
	public AuthorizationProfile getProfile(String id)throws AuthorizationException
    {
		return _mapProfiles.get(id);
	}

    /**
     * Initializes the component.
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager
        , Element eConfig) throws OAException
    {
        try
        {
            _configurationManager = oConfigurationManager;
            String sEnabled = _configurationManager.getParam(eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (sEnabled.equalsIgnoreCase("TRUE"))
                    _bEnabled = true;
                else
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " 
                        + sEnabled);
                    throw new AuthorizationException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            Element eProfile = _configurationManager.getSection(eConfig, "profile");
            while (eProfile != null)
            {
                AuthorizationProfile oProfile = 
                    new ConfigurationProfile(_configurationManager, eProfile);
                _mapProfiles.put(oProfile.getID(), oProfile);
                
                eProfile = _configurationManager.getNextSection(eProfile);
            }
        }
        catch (AuthorizationException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new AuthorizationException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Restarts the component.
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element eConfig) throws OAException
    {
        synchronized(this)
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
        if (_mapProfiles != null)
            _mapProfiles.clear();
    }

    /**
     * Returns TRUE if the component is disabled.
     * @see com.alfaariss.oa.api.IOptional#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
}