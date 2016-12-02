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
package com.alfaariss.oa.authentication.identifying;

import java.util.List;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.DetailedUserException;
import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.engine.core.user.factory.IUserFactory;
import com.alfaariss.oa.sso.authentication.service.IServiceAuthenticationMethod;
import com.alfaariss.oa.sso.authentication.web.IWebAuthenticationMethod;
import com.alfaariss.oa.util.logging.UserEventLogItem;

/**
 * The identifying authentication method is a method that authenticates users 
 * that are known in the user factory. 
 * 
 * @author EVB
 * @author MHO
 * @author JVG
 * @author Alfa & Ariss
 * 
 */
public class IdentifyingAuthenticationMethod implements IWebAuthenticationMethod, 
    IServiceAuthenticationMethod
{
    private final static String AUTHORITY_NAME = "IdentifyingAuthenticationMethod_";
    private final static String TEMPLATE_ID_PARAM = "user_id";
    private static final String DEFAULT_JSP_IDENTIFYING = "/ui/sso/authn/identifying/identifying.jsp";
    private Log _logger;
    private Log _eventLogger;
    
    private String _sMethodID;
    private boolean _bEnabled;
    private String _sFriendlyName;
    
    private String _sTemplatePath;
    
    private IConfigurationManager _configurationManager;
    private IUserFactory _oUserFactory;
    private Engine _oaEngine;
    private int _iMaxRetries;
        
    /**
     * Creates an object instance.
     */
    public IdentifyingAuthenticationMethod()
    {
        _logger = LogFactory.getLog(IdentifyingAuthenticationMethod.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
    }
    
    /**
     * Restarts the method.
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
     * Starts the method.
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException
    {
        try
        {
            if (eConfig == null || oConfigurationManager == null)
            {
                _bEnabled = false;
                _logger.error("No configuration supplied");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            _configurationManager = oConfigurationManager;
            
            _sMethodID = _configurationManager.getParam(eConfig, "id");
            if (_sMethodID == null || _sMethodID.equals(""))
            {
                _logger.error("No 'id' found in 'method' section in configuration");
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
                _oaEngine = Engine.getInstance();
                
                _oUserFactory = _oaEngine.getUserFactory();
                if (_oUserFactory == null || !_oUserFactory.isEnabled())
                {
                    _logger.error("User Factory is disabled");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }

                String sRetries = _configurationManager.getParam(eConfig, "retries");
                if(sRetries == null)
                {
                    _logger.error("No 'retries' item found in 'method' configuration with id: " 
                        + _sMethodID);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                try
                {
                    _iMaxRetries = Integer.parseInt(sRetries);
                    if(_iMaxRetries < -1)
                    {
                        _logger.error(
                            "Invalid 'retries' item found in 'method' configuration: " 
                            + sRetries);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                }
                catch (NumberFormatException e)
                {
                    _logger.error("Invalid 'retries' item found in 'method' configuration: " 
                        + sRetries);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                _logger.info("Configured retries: " + _iMaxRetries);
                
                Element eTemplate = _configurationManager.getSection(eConfig, "template");
                if(eTemplate == null)
                {
                    _sTemplatePath = DEFAULT_JSP_IDENTIFYING;
                    _logger.warn("No optional 'template' section in 'method' configuration with id: " 
                        + _sMethodID + ", using default");
                }
                else
                {
                    _sTemplatePath = _configurationManager.getParam(eTemplate, "path");
                    if(_sTemplatePath == null)
                    {
                        
                        _logger.error("No 'path' parameter found in 'template' section within 'method' configuration with id: " 
                            + _sMethodID);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                }
                _logger.info("Using JSP: " + _sTemplatePath);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during start", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
   }

    /**
     * Stops the method.
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    @Override
    public void stop()
    {
        _sTemplatePath = null;
        _sMethodID = null;
        _oaEngine = null;
        _oUserFactory = null;
        _bEnabled = false;
    }

    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    @Override
    public String getID()
    {
        return _sMethodID;
    }
    /**
     * Returns TRUE if module is enabled.
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    @Override
    public boolean isEnabled()
    { 
        return _bEnabled;
    }
    
    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    @Override
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }
    
    /**
     * @see IAuthority#getAuthority()
     */
    @Override
    public String getAuthority()
    {
        return AUTHORITY_NAME + _sMethodID;
    }

    /**'
     * TODO add user id mapping support (MHO)
     * @see IWebAuthenticationMethod#authenticate(HttpServletRequest, 
     *  HttpServletResponse, ISession)
     */
    @Override
    public UserEvent authenticate(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession) 
        throws OAException
    {
        UserEvent oUserEvent = UserEvent.AUTHN_METHOD_FAILED;
        String sUserid = null;
        try
        {   
            //DD If a user is available in the session (e.g. from SSO Session) it is leading and the user form is omitted 
            IUser oUser = oSession.getUser();
            if (oUser == null) //No user identified yet
            {
                //Check forced user
                sUserid = oSession.getForcedUserID();
                if (sUserid != null)
                {
                    oUser = _oUserFactory.getUser(sUserid);
                    if (oUser == null)
                    {        
                        throw new UserException(
                            UserEvent.AUTHN_METHOD_NOT_SUPPORTED);
                    }
                    //DD If a forced user is available in the session the user form is omitted
                }
                else //get user id from request
                {
                    sUserid = oRequest.getParameter(TEMPLATE_ID_PARAM);
                    if (sUserid == null || sUserid.trim().length() == 0)
                    {
                        //No user submitted yet
                        throw new DetailedUserException(
                            UserEvent.AUTHN_METHOD_IN_PROGRESS, new Vector<Enum>());
                    }
                    
                    //Validate submitted user
                    oUser = _oUserFactory.getUser(sUserid);
                    if (oUser == null)
                    {
                        //DD Retries == -1 means unlimited retries  
                        if (_iMaxRetries == -1)
                        {
                           throw new DetailedUserException(
                               UserEvent.AUTHN_METHOD_IN_PROGRESS, 
                               Warnings.NO_SUCH_USER_FOUND);
                        }                       
                        
                        ISessionAttributes oAttributes = oSession.getAttributes();
                        //Update retries
                        Integer intRetries = (Integer)oAttributes.get(
                            IdentifyingAuthenticationMethod.class, 
                            IWebAuthenticationMethod.RETRIES_ATTRIBUTE_NAME);
                        if (intRetries != null)
                        {
                            if (intRetries.intValue() < _iMaxRetries)
                                intRetries++;
                        }
                        else
                            intRetries = new Integer(0);
                        
                        
                        //Validate retries                    
                        if (intRetries.intValue() >= _iMaxRetries)
                        {                          
                            throw new UserException(UserEvent.USER_UNKNOWN);
                        }
                        Vector<Enum> warnings = new Vector<Enum>();
                        warnings.add(Warnings.NO_SUCH_USER_FOUND);
                        if (intRetries == _iMaxRetries - 1)
                            warnings.add(Warnings.ONE_RETRY_LEFT);                                                   
                        
                        //Update attributes
                        oAttributes.put(
                            IdentifyingAuthenticationMethod.class, 
                            IWebAuthenticationMethod.RETRIES_ATTRIBUTE_NAME, 
                            intRetries);
                        
                        throw new DetailedUserException(
                            UserEvent.AUTHN_METHOD_IN_PROGRESS, warnings);                                               
                    }                                       
                }                 
                if (!oUser.isEnabled())
                {                        
                   throw new UserException(UserEvent.USER_DISABLED);
                }                
            }                 
            if(!oUser.isAuthenticationRegistered(_sMethodID))
            {
                throw new UserException(UserEvent.AUTHN_METHOD_NOT_REGISTERED);
            }      
            
            //Everything okay
            oSession.setUser(oUser);
                        
            _eventLogger.info(new UserEventLogItem(oSession, 
                oRequest.getRemoteAddr(), UserEvent.AUTHN_METHOD_SUCCESSFUL, 
                this, null));
            
            oUserEvent = UserEvent.AUTHN_METHOD_SUCCESSFUL;
        }
        catch(DetailedUserException e)
        {
            //Non blocking error occurred - >show page                   
          _eventLogger.info(new UserEventLogItem(oSession, 
              oRequest.getRemoteAddr(), e.getEvent(), 
              this, e.getDetails().toString()));          
          forwardUser(oRequest, oResponse, oSession, e.getDetails());
          oUserEvent = e.getEvent();
        }
        catch(UserException e)
        {
          //Blocking error occurred
            _eventLogger.info(new UserEventLogItem(oSession, 
                oRequest.getRemoteAddr(), e.getEvent(), 
                this, null));            
            oUserEvent = e.getEvent();
        }        
        catch (OAException e)  //Internal error
        {
            _eventLogger.info(new UserEventLogItem(oSession, 
                oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                this, null));
            //already logged to system log. 
            throw e;
        }
        catch (Exception e)  //unknown error
        {
            if (oSession != null)
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                    this, null));
            else
                _eventLogger.info(new UserEventLogItem(null, null, 
                    null, UserEvent.INTERNAL_ERROR, null, 
                    oRequest.getRemoteAddr(), null, this, 
                    null));
            
            _logger.fatal("Fatal error during authentication", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return oUserEvent;
    }

    /**
     * @see IServiceAuthenticationMethod#authenticate(java.lang.String, byte[])
     */
    @Override
    public UserEvent authenticate(String sUserID, byte[] baCredentials) 
        throws OAException
    {
        IUser oUser = _oUserFactory.getUser(sUserID);
        if (oUser == null)
        {
            _eventLogger.info(new UserEventLogItem(
                null,null,SessionState.USER_UNKNOWN,
                UserEvent.USER_UNKNOWN,sUserID,null,null,null,null));
            
            return UserEvent.USER_UNKNOWN;
        }
        
        if (!oUser.isEnabled())
        {
            _eventLogger.info(new UserEventLogItem(
                null,null,SessionState.USER_BLOCKED,
                UserEvent.USER_DISABLED,sUserID,null,null,null,null));
            
            return UserEvent.USER_DISABLED;
        }
             
        if(!oUser.isAuthenticationRegistered(_sMethodID))
        {
            _eventLogger.info(new UserEventLogItem(
                null,null,SessionState.AUTHN_FAILED,
                UserEvent.AUTHN_METHOD_NOT_REGISTERED,sUserID,null,null,null,null));
            
            return UserEvent.AUTHN_METHOD_FAILED;
        }
        
        _eventLogger.info(new UserEventLogItem(
            null,null,SessionState.AUTHN_OK,
            UserEvent.AUTHN_METHOD_SUCCESSFUL,sUserID,null,null,null,null));

        return UserEvent.AUTHN_METHOD_SUCCESSFUL;
    }
    
    private void forwardUser(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession, List<Enum> warnings) 
        throws OAException
    {
        try
        {               
            oRequest.setAttribute(ISession.ID_NAME, oSession.getId());
            oRequest.setAttribute(ISession.LOCALE_NAME, oSession.getLocale());
            
            if(warnings != null)
            {
                oRequest.setAttribute(
                    DetailedUserException.DETAILS_NAME, warnings);
            }
            
            oRequest.setAttribute(
                IWebAuthenticationMethod.AUTHN_METHOD_ATTRIBUTE_NAME, 
                _sFriendlyName);
            oRequest.setAttribute(Server.SERVER_ATTRIBUTE_NAME, 
                _oaEngine.getServer());
            
            RequestDispatcher oDispatcher = oRequest.getRequestDispatcher(_sTemplatePath);
            if(oDispatcher == null)
            {
                _logger.warn("There is no request dispatcher supported with name: " 
                    + _sTemplatePath);                    
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            _logger.debug("Forward user to: " + _sTemplatePath);
            
            oSession.persist();
            
            oDispatcher.forward(oRequest, oResponse);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            if (oSession != null)
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                    this, null));
            else
                _eventLogger.info(new UserEventLogItem(null, null, 
                    null, UserEvent.INTERNAL_ERROR, null, 
                    oRequest.getRemoteAddr(), null, this, 
                    null));
            
            _logger.fatal("Internal error during forward", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
}
