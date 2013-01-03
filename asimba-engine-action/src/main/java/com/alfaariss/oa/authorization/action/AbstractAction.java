/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authorization.action;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.authorization.IAuthorizationAction;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.attribute.AttributeException;

/**
 * Provides standard functionality used by all actions.
 *
 * This class is responsible for reading the mandatory parts of action configuration,
 * such as the 'enabled' status and the action ID. 
 *  
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public abstract class AbstractAction implements IAuthorizationAction
{
    /** The configuration manager */
    protected IConfigurationManager _configManager = null;

    private Log _logger;
    private boolean _bIsEnabled;
    private String _sActionID;
    private String _sFriendlyName;
    
    /**
     * Default constructor
     */
    public AbstractAction() 
    {
        _logger = LogFactory.getLog(AbstractAction.class); 
        _bIsEnabled = false;
    }

    /**
     * @see IAuthorizationAction#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager,
        Element eConfig) throws OAException
    {
        if(eConfig == null)
            throw new IllegalArgumentException(
                "Supplied configuration section empty");
        if (oConfigurationManager == null)
            throw new IllegalArgumentException(
                "Supplied configurationmanager empty");
        
        _configManager = oConfigurationManager;
        
        _bIsEnabled = true;
        String sEnabled = _configManager.getParam(eConfig, "enabled");
        if (sEnabled != null)
        {
            if (sEnabled.equalsIgnoreCase("FALSE"))
                _bIsEnabled = false;
            else if (sEnabled.equalsIgnoreCase("TRUE"))
            {
                _bIsEnabled = true;
            }
            else
            {
                _logger.error("Unknown value in 'enabled' action configuration item: " + sEnabled);
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        
        _sActionID = _configManager.getParam(eConfig, "id");
        if (_sActionID == null || "".equals(_sActionID))
        {
            _logger.error("No id found for authorization action");
            throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
         }
        
        _sFriendlyName = _configManager.getParam(eConfig, "friendlyname");
        if (_sFriendlyName == null)
        {
            _logger.error("No 'friendlyname' parameter found in action configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
    }

    /**
     * @see com.alfaariss.oa.api.authorization.IAuthorizationAction#stop()
     */
    public void stop()
    {
        _bIsEnabled = false;
    }
    
    /**
     * @see com.alfaariss.oa.api.authorization.IAuthorizationAction#getID()
     */
    public String getID()
    {
        return _sActionID;
    }

    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

    /**
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bIsEnabled;
    }
}
