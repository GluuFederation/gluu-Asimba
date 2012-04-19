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
package com.alfaariss.oa.authentication.guest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.IManagebleItem;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.authentication.guest.bean.GuestUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.user.factory.IUserFactory;
import com.alfaariss.oa.sso.authentication.service.IServiceAuthenticationMethod;
import com.alfaariss.oa.sso.authentication.web.IWebAuthenticationMethod;
import com.alfaariss.oa.util.logging.UserEventLogItem;

/**
 * Guest authentication method.
 *
 * Creates a guest user object with the configured user id.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class GuestAuthenticationMethod implements IWebAuthenticationMethod, IServiceAuthenticationMethod 
{
	private final static String AUTHORITY_NAME = "GuestAuthenticationMethod_";
	private Log _logger;
	private Log _eventLogger;
    
	private boolean _bEnabled;
    private String _sMethodId;
    private String _sFriendlyName;
    
    private IConfigurationManager _configurationManager;
    private IUserFactory _oUserFactory;
	private String _sDefaultUserId;
    private String _sMyOrganization;
    
	
	/**
	 * Constructor. 
	 */
	public GuestAuthenticationMethod()
	{
		_logger = LogFactory.getLog(GuestAuthenticationMethod.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
        _sDefaultUserId = "";
        _sMethodId = "";
        _sMyOrganization = "";
	}
    
    /**
     * @see IManagebleItem#getID()
     */
    public String getID()
    {
        return _sMethodId;
    }
	
	/**
	 * @see IManagebleItem#isEnabled()
	 */
	public boolean isEnabled() 
	{
		return _bEnabled;
	}

	/**
	 * @see IComponent#restart(org.w3c.dom.Element)
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
	 * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
	 */
	public void start(IConfigurationManager oConfigurationManager, 
		Element eConfig) throws OAException 
	{
		try
        {
            if (eConfig == null || oConfigurationManager == null)
            {
                _logger.error("No configuration supplied");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            _configurationManager = oConfigurationManager;
            
            _oUserFactory = Engine.getInstance().getUserFactory();
            if (_oUserFactory == null || !_oUserFactory.isEnabled())
            {
                _logger.error("User Factory is disabled");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            _sMethodId = _configurationManager.getParam(eConfig, "id");
            if (_sMethodId == null)
            {
            	_logger.error("No 'id' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sFriendlyName = _configurationManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null)
            {
                _logger.error("No 'friendlyname' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
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
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            if (_bEnabled)
            {
                Element eUser = _configurationManager.getSection(eConfig, "user");
                if(eUser == null)
                {
                    _logger.error("No 'user' section in 'method' configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                _sDefaultUserId = _configurationManager.getParam(eUser, "id");
                if(_sDefaultUserId == null)
                {
                    _logger.error("No 'id' parameter found in 'user' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (_sDefaultUserId.trim().length() == 0)
                {
                	_logger.error("Empty 'id' parameter found in 'user' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                _sMyOrganization = Engine.getInstance().getServer().getOrganization().getID();
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during start", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
	}

	/**
	 * @see com.alfaariss.oa.api.IComponent#stop()
	 */
	public void stop() 
	{
		_bEnabled = false;
		_sDefaultUserId = "";
		_sMethodId = "";
		_oUserFactory = null;      
	}

	/**
	 * @see IAuthority#getAuthority()
	 */
	public String getAuthority() 
	{
		return AUTHORITY_NAME + _sMethodId;
	}
	
	/**
	 * @see IWebAuthenticationMethod#authenticate(
	 *     javax.servlet.http.HttpServletRequest, 
	 *     javax.servlet.http.HttpServletResponse, ISession)
	 */
	public UserEvent authenticate(HttpServletRequest oRequest, 
		HttpServletResponse oResponse, ISession oSession) 
		throws OAException 
	{
        UserEvent oUserEvent = UserEvent.AUTHN_METHOD_FAILED;
        
        try
        {   
            IUser oUser = oSession.getUser();
            if (oUser == null)
            {
                String sUserId = oSession.getForcedUserID(); 
                if (sUserId == null)
                    sUserId = _sDefaultUserId;
                
                oUser = _oUserFactory.getUser(sUserId);
                if (oUser == null) 
                {
                    //DD User not available in session; create a guest user
                    oUser = new GuestUser(_sMyOrganization, sUserId, _sMethodId);
                }
               
                if (!oUser.isEnabled())
                    throw new UserException(UserEvent.USER_DISABLED);
                
                // Check is user is registered for this guest method
                if(!oUser.isAuthenticationRegistered(_sMethodId))
                {
                    throw new UserException(UserEvent.AUTHN_METHOD_NOT_REGISTERED);
                }
           
                oSession.setUser(oUser);
            }
            else if(!oUser.isAuthenticationRegistered(_sMethodId))
            {                
                throw new UserException(UserEvent.AUTHN_METHOD_NOT_REGISTERED);
            }
                        
            oUserEvent = UserEvent.AUTHN_METHOD_SUCCESSFUL;
            
            _eventLogger.info(new UserEventLogItem(oSession, 
                oRequest.getRemoteAddr(), UserEvent.AUTHN_METHOD_SUCCESSFUL, 
                this, null));
        }
        catch(UserException e)
        {
            oUserEvent = e.getEvent();
            _eventLogger.info(new UserEventLogItem(oSession, 
                oRequest.getRemoteAddr(), oUserEvent, 
                this, null));            
        }
        catch (Exception e)
        {
            if (oSession != null)
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                    this, e.getMessage()));
            else
                _eventLogger.info(new UserEventLogItem(null, null, 
                    null, UserEvent.INTERNAL_ERROR, null, 
                    oRequest.getRemoteAddr(), null, this, 
                    e.getMessage()));
            
            _logger.fatal("Fatal error during authentication", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
        
        return oUserEvent;
	}

    /**
     * @see IServiceAuthenticationMethod#authenticate(java.lang.String, byte[])
     */
    public UserEvent authenticate(String sUserID, byte[] baCredentials) 
        throws OAException
    {
        _eventLogger.info(new UserEventLogItem(null,null,SessionState.AUTHN_OK,
            UserEvent.AUTHN_METHOD_SUCCESSFUL,sUserID, null,null,null,null));
        
        return UserEvent.AUTHN_METHOD_SUCCESSFUL;
    }

    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

}
