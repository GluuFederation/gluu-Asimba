/*
 * * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authorization.method.web;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.authorization.IAuthorizationAction;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.attribute.AttributeException;
import com.alfaariss.oa.sso.authorization.web.IWebAuthorizationMethod;

/**
 * This class provides functionality that is used by all <code>AuthorizationMethod</code>s
 * 
 * This functionality mostly involves component items, such as start and stop.
 *
 * @author Alfa & Ariss
 *
 */
public abstract class AbstractWebAuthorizationMethod implements IWebAuthorizationMethod
{
    /** The configuration manager, initialized through the abstract <code>start</code> method */
    protected IConfigurationManager _configManager = null;
    /** Action that will be performed if the user meets the method requirements */
    protected IAuthorizationAction _oAction;
    /** The method ID. */
    protected String _sId;
    
    private boolean _bIsEnabled = false;    
    private Log _logger;
    private String _sFriendlyName;

    
    /**
     * Constructor. 
     */
    public AbstractWebAuthorizationMethod()
    {
        _logger =  LogFactory.getLog(AbstractWebAuthorizationMethod.class);
    }
    
    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    public String getID()
    {
        return _sId;
    }
    
    /**
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bIsEnabled;
    }

    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

    /**
     * @see IWebAuthorizationMethod#start(IConfigurationManager, 
     *  org.w3c.dom.Element, java.util.Map)
     */
    public void start(IConfigurationManager oConfigurationManager,
        Element eConfig, Map<String,IAuthorizationAction> mapActions) throws OAException
    {
        
        if(eConfig == null)
            throw new IllegalArgumentException(
                "Supplied configuration section empty");
        if (oConfigurationManager == null)
            throw new IllegalArgumentException(
                "Supplied configurationmanager empty");
        
        _configManager = oConfigurationManager;
        
        _sId = _configManager.getParam(eConfig, "id");
        if (_sId == null || "".equals(_sId))
        {
            _logger.error("No id found for authorization method");
            throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
         }
        
        _sFriendlyName = _configManager.getParam(eConfig, "friendlyname");
        if (_sFriendlyName == null)
        {
            _logger.error("No 'friendlyname' parameter found in configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _bIsEnabled = true;//default enabled
        
        String sEnabled = _configManager.getParam(eConfig, "enabled");
        if (sEnabled != null)
        {
            if (sEnabled.equalsIgnoreCase("FALSE"))
                _bIsEnabled = false;
            else if (!sEnabled.equalsIgnoreCase("TRUE"))
            {
                StringBuffer sbError = new StringBuffer("Unknown value in 'enabled' configuration item: ");
                sbError.append(sEnabled);
                sbError.append(", for authZ method ");
                sbError.append(_sId);
                _logger.error(sbError.toString());
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        
        StringBuffer sbInfo = new StringBuffer("Authorization method (");
        sbInfo.append(_sId);
        sbInfo.append("): ");
        if (_bIsEnabled)
            sbInfo.append("enabled");
        else
            sbInfo.append("disabled");
        
        String sActionID = _configManager.getParam(eConfig, "action");
        if (sActionID == null)
        {
            _logger.error("Value 'action' not found for authZ method " + _sId);
            throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _oAction = mapActions.get(sActionID);
        if (_oAction == null)
        {
            _logger.error("Unknown 'action' item found in configuration: " + sActionID);
            throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
        }
            
    }

    /**
     * @see com.alfaariss.oa.sso.authorization.web.IWebAuthorizationMethod#stop()
     */
    public void stop()
    {
        _bIsEnabled = false;
    }

}
