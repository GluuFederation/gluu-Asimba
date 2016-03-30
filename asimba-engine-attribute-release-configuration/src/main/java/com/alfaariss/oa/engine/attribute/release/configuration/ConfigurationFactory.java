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
import java.util.HashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.attribute.AttributeException;
import com.alfaariss.oa.engine.core.attribute.release.IAttributeReleasePolicy;
import com.alfaariss.oa.engine.core.attribute.release.factory.IAttributeReleasePolicyFactory;


/**
 * Release policy factory.
 *
 * Reads the policy information from the configuration document.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ConfigurationFactory implements IAttributeReleasePolicyFactory, 
    IComponent 
{
    private static Log _logger;
    private IConfigurationManager _configurationManager;
    private boolean _bEnabled;
    private HashMap<String, ConfigurationPolicy> _mapPolicies;
    
	/**
	 * Creates the object. 
	 */
	public ConfigurationFactory()
    {
        _logger = LogFactory.getLog(ConfigurationFactory.class);
        _mapPolicies = new HashMap<String, ConfigurationPolicy>();
        _bEnabled = false;
    }

    /**
     * Returns the policy with the supplied name or <code>null</code> if 
     * it does not exist.
     * @see IAttributeReleasePolicyFactory#getPolicy(java.lang.String)
     */
    @Override
    public IAttributeReleasePolicy getPolicy(String sPolicy)
    {
        return _mapPolicies.get(sPolicy);
    }

    /**
     * Returns TRUE if this release policy factory is enabled.
     * @see com.alfaariss.oa.api.IOptional#isEnabled()
     */
    @Override
    public boolean isEnabled()
    {
        return _bEnabled;
    }

    /**
     * Initializes the release policy factory.
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws OAException
    {
        try
        {
            _configurationManager = oConfigurationManager;
            _bEnabled = true;
            String sEnabled = _configurationManager.getParam(eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " 
                        + sEnabled);
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            Element ePolicy = _configurationManager.getSection(eConfig, "policy");
            while (ePolicy != null)
            {
                ConfigurationPolicy oPolicy = 
                    new ConfigurationPolicy(_configurationManager, ePolicy);
                _mapPolicies.put(oPolicy.getID(), oPolicy);
                
                ePolicy = _configurationManager.getNextSection(ePolicy);
            }
        }
        catch (AttributeException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL, e);
        }
    }

    /**
     * Restarts the release policy factory.
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    @Override
    public void restart(Element eConfig) throws OAException
    {
        synchronized(this)
        {
            stop();
            start(_configurationManager, eConfig);
        }
    }

    /**
     * Stops the release policy factory.
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    @Override
    public void stop()
    {
        _bEnabled = false;
        if (_mapPolicies != null)
            _mapPolicies.clear();
    }
}