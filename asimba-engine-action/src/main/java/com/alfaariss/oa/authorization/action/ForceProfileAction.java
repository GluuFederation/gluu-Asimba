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

import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;
import com.alfaariss.oa.engine.core.authentication.factory.IAuthenticationProfileFactory;

/**
 * Action that changes the user authentication profile to the configured profile.
 *
 * @author MHO
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public class ForceProfileAction extends AbstractAction
{
    private Log _logger;
    private IAuthenticationProfileFactory _authenticationProfileFactory;
    private String _sForceProfile;

    /**
     * Constructor
     */
    public ForceProfileAction()
    {
        _logger = LogFactory.getLog(ForceProfileAction.class); 
        _sForceProfile = null;
    }
    
    /**
     * @see com.alfaariss.oa.api.authorization.IAuthorizationAction#perform(com.alfaariss.oa.api.session.ISession)
     */
    @Override
    public UserEvent perform(ISession oSession) throws OAException
    {
        AuthenticationProfile authNProfile = _authenticationProfileFactory.getProfile(_sForceProfile);
        if (authNProfile == null)
        {
            _logger.error("Unknown Authentication Profile configured: " + _sForceProfile);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        if (!authNProfile.isEnabled())
        {
            _logger.error("Configured Authentication Profile is disabled: " + _sForceProfile);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        List<IAuthenticationProfile> listProfiles = new Vector<IAuthenticationProfile>();
        listProfiles.add(authNProfile);
        
        oSession.setAuthNProfiles(listProfiles);
        return UserEvent.AUTHZ_METHOD_SUCCESSFUL;
    }

    /**
     * Extra start method that is used to read the profile ID.
     * 
     * @see AbstractAction#start(IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager oConfigurationManager,
        Element eConfig) throws OAException
    {
        super.start(oConfigurationManager, eConfig);
        
        Element eProfile = _configManager.getSection(eConfig, "forcedprofile");
        if (eProfile == null)
        {
            _logger.error("No 'forcedprofile' section found in action configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _sForceProfile = _configManager.getParam(eProfile, "id");
        if (_sForceProfile == null)
        {
            _logger.error("No config item 'profile' in Pre authR action configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

        _authenticationProfileFactory = Engine.getInstance().getAuthenticationProfileFactory();
        
        AuthenticationProfile authNProfile = _authenticationProfileFactory.getProfile(_sForceProfile);
        if (authNProfile == null)
        {
            _logger.error("Unknown Authentication Profile configured: " + _sForceProfile);
            throw new OAException(SystemErrors.ERROR_INIT);
        }
        
        if (!authNProfile.isEnabled())
        {
            _logger.warn("Configured Authentication Profile is disabled: " + _sForceProfile);
        }
    }

}
