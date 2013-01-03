/*
 * * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authorization.method.web.forceaction;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.authorization.IAuthorizationAction;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.authorization.method.web.AbstractWebAuthorizationMethod;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.util.logging.UserEventLogItem;

/**
 * Authorization method that always performs the configured action.
 *
 * This authorization method performs the action that is defined in the 
 * configuration for this method, it does not look at request properties. 
 * 
 * @author MHO
 * @author JRE
 * @author Alfa & Ariss
 */
public class ForceActionAuthorizationMethod extends AbstractWebAuthorizationMethod 
{
    private final static String AUTHORITY_NAME = "ForceActionAuthZMethod_";
    private Log _logger;
    private Log _eventLogger;

    /**
     * Constructor
     */
    public ForceActionAuthorizationMethod()
    {
        _logger = LogFactory.getLog(ForceActionAuthorizationMethod.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
    }
    
    /**
     * @see AbstractWebAuthorizationMethod#start(IConfigurationManager, org.w3c.dom.Element, java.util.Map)
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig, Map<String,IAuthorizationAction> mapActions) throws OAException
    {
        super.start(oConfigurationManager, eConfig, mapActions);
        _logger.info("Authorization method loaded properly: " + _sId);
    }

    /**
     * @see com.alfaariss.oa.sso.authorization.web.IWebAuthorizationMethod#authorize(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, com.alfaariss.oa.api.session.ISession)
     */
    public UserEvent authorize(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession) 
        throws OAException
    {
        UserEvent event = _oAction.perform(oSession);
        
        _eventLogger.info(new UserEventLogItem(oSession, 
            oRequest.getRemoteAddr(), event, this, null));
        
        return event;
    }
    
    /**
     * @see IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME + _sId;
    }

}
