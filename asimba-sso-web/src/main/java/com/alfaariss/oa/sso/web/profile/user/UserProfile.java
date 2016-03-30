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
package com.alfaariss.oa.sso.web.profile.user;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.DetailedUserException;
import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.IService;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.api.sso.ISSOProfile;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.TGTEventError;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.authentication.factory.IAuthenticationProfileFactory;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.sso.web.WebSSOServlet;
import com.alfaariss.oa.sso.web.profile.logout.LogoutProfile;
import com.alfaariss.oa.sso.web.profile.logout.LogoutState;
import com.alfaariss.oa.sso.web.profile.user.info.IAttribute;
import com.alfaariss.oa.sso.web.profile.user.info.UserAttribute;
import com.alfaariss.oa.sso.web.profile.user.info.UserInfo;
import com.alfaariss.oa.util.logging.RequestorEventLogItem;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.validation.SessionValidator;
import com.alfaariss.oa.util.validation.TGTValidator;
import com.alfaariss.oa.util.web.CookieTool;
import com.alfaariss.oa.util.web.HttpUtils;

/**
 * User page implementation.
 *
 * Supports:
 * <ul>
 *  <li>Showing user information if valid TGT is available (including the userattributes)</li>
 *  <li>Optionally showing an 'authenticate' button when no TGT is available</li>
 *  <li>Single logout support by using a logout page</li>
 * </ul>
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class UserProfile implements ISSOProfile, IService, IAuthority
{
    /** Profile ID: user */
    public final static String PROFILE_ID = "user";
    
    private final static String AUTHORITY_NAME = "UserProfile";
    
    private final static String JSP_AUTHN_ENABLED = "authnEnabled";
    
    private final static String TARGET_AUTHN = "authn";
    private final static String TARGET_LOGOUT = "logout";
    
    private final static String DEFAULT_JSP_INDEX = "/ui/sso/user/index.jsp";
    private final static String DEFAULT_REQUESTOR_ID = "userpage";
    
    private static Log _logger;
    private static Log _eventLogger;
    
    private ITGTFactory<?> _tgtFactory;
    private ISessionFactory<?> _sessionFactory;
    private IRequestorPoolFactory _requestorPoolFactory;
    private IAuthenticationProfileFactory _authenticationProfileFactory;
    
    private CookieTool _cookieTool;
    
    private String _sRedirectURL;
    private String _sJSPUserIndex;
    private String _sUserPageRequestorId;
    private boolean _bAuthNEnabled;
    
    /**
     * Constructor. 
     */
    public UserProfile()
    {
        _logger = LogFactory.getLog(UserProfile.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
        
        _cookieTool = null;
        _sJSPUserIndex = null;
        _sUserPageRequestorId = null;
        _sRedirectURL = null;
        _bAuthNEnabled = true;
    }
    
    /**
     * @see com.alfaariss.oa.api.sso.ISSOProfile#destroy()
     */
    @Override
    public void destroy()
    {
        _sJSPUserIndex = null;
        _sUserPageRequestorId = null;
        _sRedirectURL = null;
        _cookieTool = null;
        _bAuthNEnabled = true;
    }

    /**
     * @see com.alfaariss.oa.api.sso.ISSOProfile#getID()
     */
    @Override
    public String getID()
    {
        return PROFILE_ID;
    }

    /**
     * @param eSpecific is always supplied as NULL
     * @see com.alfaariss.oa.api.sso.ISSOProfile#init(javax.servlet.ServletContext, com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element, org.w3c.dom.Element)
     */
    @Override
    public void init(ServletContext context, 
        IConfigurationManager configurationManager, Element eParent, 
        Element eSpecific) throws OAException
    {
        Engine engine = Engine.getInstance();
        _tgtFactory = engine.getTGTFactory();
        _sessionFactory = engine.getSessionFactory();
        _requestorPoolFactory = engine.getRequestorPoolFactory();
        _authenticationProfileFactory = 
            engine.getAuthenticationProfileFactory();      
        
        _cookieTool = new CookieTool(configurationManager, eParent);
        
        readConfigRedirectURL(configurationManager, eParent);
        
        Element eUserPage = configurationManager.getSection(eParent, "userpage");
        if (eUserPage == null)
        {
            _logger.warn("No 'userpage' section available in configuration, using defaults");
            _sJSPUserIndex = DEFAULT_JSP_INDEX;
            _sUserPageRequestorId = DEFAULT_REQUESTOR_ID;
            _sRedirectURL = null;
            _bAuthNEnabled = isSSOEnabledInWebSSO(configurationManager, eParent);//default = true if single sign-on is enabled in websso
            if (!_bAuthNEnabled)
                _logger.warn("Single Sign-On is disabled; Default setting is set to disabled for authentication within the user page");
        }
        else
        {
            readConfig(configurationManager, eParent, eUserPage);
        }
        
        _logger.info("Started User Profile: " + PROFILE_ID);
    }

    /**
     * @see com.alfaariss.oa.api.IService#service(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    public void service(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) throws OAException
    {
        ISession session = null;
        try
        {
            //Disable caching
            HttpUtils.setDisableCachingHttpHeaders(servletRequest, servletResponse);     
            
            session = (ISession)servletRequest.getAttribute(ISession.ID_NAME); 
            if (session == null)
            {
                String sId = servletRequest.getParameter(ISession.ID_NAME);
                if(sId != null)
                {
                    if(!SessionValidator.validateDefaultSessionId(sId))
                    {
                        _logger.warn("Invalid session id in request: " + sId);
                        throw new UserException(UserEvent.REQUEST_INVALID);
                    }
                    session = _sessionFactory.retrieve(sId);
                }
            }
            
            String sTarget = resolveTarget(servletRequest);
            if (sTarget != null)
            {
                if (sTarget.equalsIgnoreCase(TARGET_AUTHN) && _bAuthNEnabled)
                {
                    _logger.debug("Performing 'authn' request sent from IP: " 
                        + servletRequest.getRemoteAddr());
                    processAuthN(servletRequest, servletResponse, session);
                    return;
                }
                else if (sTarget.equalsIgnoreCase(TARGET_LOGOUT))
                {
                    _logger.debug("Performing 'logout' request sent from IP: " 
                        + servletRequest.getRemoteAddr());
                    processLogout(servletRequest, servletResponse, session);
                    return;
                }
            }
            
            _logger.debug("Performing 'info' request sent from IP: " 
                + servletRequest.getRemoteAddr());
            processDefault(servletRequest, servletResponse, session);
        }
        catch (UserException e)
        {
            try
            {
                if (!servletResponse.isCommitted())
                    servletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
            catch (IOException e1)
            {
                _logger.debug("Could not respond", e1);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        catch(OAException e)
        {
            if (session != null)
                _eventLogger.info(new RequestorEventLogItem(session, 
                    servletRequest.getRemoteAddr(), 
                    RequestorEvent.INTERNAL_ERROR, this, null));
            else
                _eventLogger.info(new RequestorEventLogItem(null, null, 
                    null,RequestorEvent.INTERNAL_ERROR, null, 
                    servletRequest.getRemoteAddr(), null, this, null));
            
            throw e;
        }
        catch (Exception e)
        {
            if (session != null)
                _eventLogger.info(new RequestorEventLogItem(session, 
                    servletRequest.getRemoteAddr(), 
                    RequestorEvent.INTERNAL_ERROR, this, null));
            else
                _eventLogger.info(new RequestorEventLogItem(null, null, 
                    null,RequestorEvent.INTERNAL_ERROR, null, 
                    servletRequest.getRemoteAddr(), null, this, null));
            
            _logger.fatal("Internal error during request processing", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * @see com.alfaariss.oa.api.logging.IAuthority#getAuthority()
     */
    @Override
    public String getAuthority()
    {
        return AUTHORITY_NAME;
    }

    private void readConfigRedirectURL(IConfigurationManager configurationManager, 
        Element config) throws OAException
    {
        _sRedirectURL = configurationManager.getParam(config, "redirect_url");
        if (_sRedirectURL == null)
        {
            _logger.info("No optional 'redirect_url' parameter found in configuration");
        }
        else
        {
            if (!_sRedirectURL.endsWith("/"))
                _sRedirectURL = _sRedirectURL + "/";
            
            _sRedirectURL = _sRedirectURL + PROFILE_ID;
                        
            try
            {
                new URL(_sRedirectURL);
            }
            catch (MalformedURLException e)
            {
                _logger.error("The configured 'redirect_url' parameter isn't a valid URL: " 
                    + _sRedirectURL, e);
                
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            
            _logger.info("Using configured 'redirect_url' parameter: " + _sRedirectURL);
        }
    }
    
    private void readConfig(IConfigurationManager configurationManager, 
        Element eParent, Element config) throws OAException
    {
        Element eJSP = configurationManager.getSection(config, "jsp");
        if (eJSP == null)
        {
            _logger.warn("No optional 'jsp' section found in 'userpage' section in configuration; using default");
            _sJSPUserIndex = DEFAULT_JSP_INDEX;
        }
        else
        {
            _sJSPUserIndex = configurationManager.getParam(eJSP, "path");
            if (_sJSPUserIndex == null)
            {
                _logger.error("No 'path' parameter found in 'jsp' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        _logger.info("Using user info jsp location: " + _sJSPUserIndex);
        
        _sUserPageRequestorId = configurationManager.getParam(config, "requestor");
        if (_sUserPageRequestorId == null)
        {
            _sUserPageRequestorId = DEFAULT_REQUESTOR_ID;
            _logger.warn("No optional 'requestor' parameter found in 'userpage' section in configuration");
        }
        
        _logger.info("Userpage will use requestor id: " + _sUserPageRequestorId);
        
        _bAuthNEnabled = isSSOEnabledInWebSSO(configurationManager, eParent);
        if (!_bAuthNEnabled)
            _logger.warn("Single Sign-On is disabled; Default setting is set to disabled for authentication within the user page");
        
        Element eAuthN = configurationManager.getSection(config, "authn");
        if (eAuthN == null)
        {
            _logger.warn("No optional 'authn' section found in 'userpage' section in configuration; using authentication enabled: " + _bAuthNEnabled);
        }
        else
        {
            String sEnabled = configurationManager.getParam(eAuthN, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bAuthNEnabled = false;
                else if (sEnabled.equalsIgnoreCase("TRUE"))
                    _bAuthNEnabled = true;
                else
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " 
                        + sEnabled);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }   
            }
        }
        
        _logger.info("Authentication for Userpage is: " + (_bAuthNEnabled ? "enabled" : "disabled"));
        
        if (_bAuthNEnabled)
        {//only verify if enabled, when requestor id is used during authentication
            IRequestor requestor = _requestorPoolFactory.getRequestor(_sUserPageRequestorId);
            if (requestor == null)
                _logger.warn("Unknown 'requestor' configured; Requestor is not available in any requestorpool: " + _sUserPageRequestorId);
            else if (!requestor.isEnabled())
                _logger.warn("Disabled 'requestor' configured; Requestor is disabled: " + _sUserPageRequestorId);
        }
    }
    
    private boolean isSSOEnabledInWebSSO(IConfigurationManager configurationManager, 
        Element config) throws OAException
    {
        String sSingleSignOn = configurationManager.getParam(config, "single_sign_on");
        if (sSingleSignOn != null)
        {
            if("false".equalsIgnoreCase(sSingleSignOn))
            {
                _logger.info("Single sign-on is disabled in the Web SSO");
                return false;
            }
            else if (!"true".equalsIgnoreCase(sSingleSignOn))
            {
                _logger.error("Invalid value for 'single_sign_on' item found in websso configuration: " 
                    + sSingleSignOn);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        
        return true;
    }
    
    private String resolveTarget(HttpServletRequest servletRequest) 
    {
        String sRequestURI = servletRequest.getRequestURI();
        if (!sRequestURI.endsWith("/"))
            sRequestURI = sRequestURI + "/";
        sRequestURI = sRequestURI.toLowerCase();
        
        int iIndex = sRequestURI.indexOf(PROFILE_ID + "/");
        if (iIndex > -1)
        {
            int iStart = iIndex + PROFILE_ID.length() + "/".length();
            if (sRequestURI.length() > iStart)
            {
                String target = sRequestURI.substring(iStart, sRequestURI.length() -1);
                if (target.length() > 0)
                    return target;
            }
        }

        return null;
    }
    
    @SuppressWarnings({"unchecked"}) //sessionAttributes cast
    private void processDefault(HttpServletRequest servletRequest, 
        HttpServletResponse servletResponse, ISession session) throws OAException
    {
        boolean bShowAuthNButton = _bAuthNEnabled;
        Enum error = null;
        List<TGTEventError> warnings = new Vector<TGTEventError>();
        
        String sTGTCookie = _cookieTool.getCookieValue(
            WebSSOServlet.TGT_COOKIE_NAME, servletRequest);
        
        if (session == null)
        {
            ITGT oTgt = null;

            if(sTGTCookie != null)
            {
                //Verify cookie value
                if(TGTValidator.validateDefaultTGTId(sTGTCookie))
                {        
                    oTgt = _tgtFactory.retrieve(sTGTCookie);
                }
                else
                {
                    _logger.debug("TGT cookie contains invalid TGT ID: " + sTGTCookie);
                    _cookieTool.removeCookie(WebSSOServlet.TGT_COOKIE_NAME, 
                        servletRequest, servletResponse);
                    _logger.debug("TGT cookie removed");
                }            
            }
            
            if(oTgt != null)
            { 
                if (!oTgt.isExpired()) //TGT valid
                {
                    if (bShowAuthNButton)
                    {
                        if (verifyRequestorEnabled(oTgt))
                        {//populate session with TGT information
                            
                            _logger.debug("Valid TGT available, but no session available with user attributes");
                            processAuthN(servletRequest, servletResponse, null);
                            return;
                        }
                        bShowAuthNButton = false;//disable button, the requestor is not enabled
                    }
                    
                    UserInfo userInfo = getUserInfo(session, oTgt);
                    if (userInfo != null)
                    {
                        servletRequest.setAttribute(UserInfo.USER_INFO_NAME, userInfo);
                    }
                }
                else
                {
                    //TGT is expired, so can be persisted
                    oTgt.persist();
                  //no valid TGT found
                    error = Errors.NO_TGT;
                }
            }
            else
            {//no valid TGT found
                error = Errors.NO_TGT;
            }
            
        }
        else if (sTGTCookie == null 
            && session.getState() != SessionState.USER_LOGOUT_SUCCESS)
        {//tgt already expired
            String sTGTID = session.getTGTId();
            if (sTGTID != null)
            {
                ITGT tgt = _tgtFactory.retrieve(sTGTID);
                if (tgt != null && !tgt.isExpired())
                {
                    tgt.expire();
                    tgt.persist();
                    _logger.debug("Removed TGT: " + sTGTID);
                }
            }
            
            //no valid TGT found
            switch (session.getState())
            {
                case AUTHN_FAILED:
                case USER_CANCELLED:
                case POST_AUTHZ_FAILED:
                case PRE_AUTHZ_FAILED:
                {
                    error = session.getState();
                    break;
                }
                case USER_BLOCKED:
                case USER_UNKNOWN:
                {//force authn failed, so userpage cannot be used to search for existing users
                    error = SessionState.AUTHN_FAILED;
                    break;
                }
                default:
                {
                    error = Errors.NO_TGT;
                }
            }            
            
            session.expire();
            session.persist();
            
            _logger.debug("Removed session: " + session.getId());   
        }
        else
        {
            switch (session.getState())
            {
                case AUTHN_OK:
                {
                    String sTGTId = session.getTGTId();
                    if (sTGTId != null) //TGT Cookie found
                    {
                        ITGT oTgt = _tgtFactory.retrieve(sTGTId);
                        if (oTgt != null && !oTgt.isExpired())
                        {
                            //update user info with user attributes
                            UserInfo userInfo = getUserInfo(session, oTgt);
                            if (userInfo != null)
                            {
                                servletRequest.setAttribute(UserInfo.USER_INFO_NAME, userInfo);
                                break;
                            }
                        }
                    }
                    
                    error = Errors.NO_TGT;
                    
                    //session is invalid, so can be removed.
                    session.expire();
                    session.persist();
                    break;
                }
                case USER_LOGOUT_PARTIAL:
                case USER_LOGOUT_FAILED:
                {
                    ISessionAttributes sessionAttributes = session.getAttributes();
                    if (sessionAttributes.contains(LogoutState.class, LogoutState.SESSION_LOGOUT_RESULTS))
                    {                        
                        if (sessionAttributes.contains(LogoutState.class, LogoutState.SESSION_LOGOUT_RESULTS))
                        {
                            List<TGTEventError> totalWarnings = (List<TGTEventError>)sessionAttributes.get(
                                LogoutState.class, LogoutState.SESSION_LOGOUT_RESULTS);
                            
                            for (int i = 0; i < totalWarnings.size(); i++)
                            {//DD Only add failed logout calls
                                TGTEventError eventError = totalWarnings.get(i);
                                if (eventError.getCode() != UserEvent.USER_LOGGED_OUT)
                                {
                                    warnings.add(eventError);
                                }
                            }
                        }
                    }
                    
                    //Disable authenticate button, because the user explicitly wanted to logout. 
                    bShowAuthNButton = false;
                    
                    error = session.getState();

                    _eventLogger.info(new UserEventLogItem(session, 
                        servletRequest.getRemoteAddr(), 
                        UserEvent.USER_LOGOUT_FAILED, this, null));
                    
                    //session contains error, so can be removed.
                    if (session.getId() != null)
                    {//only remove if session has already peristed yet, during partial logout this may not be the case
                        session.expire();
                        session.persist();
                    }
                    
                    break;
                }
                case USER_LOGOUT_SUCCESS:
                {
                    _eventLogger.info(new UserEventLogItem(session, 
                        servletRequest.getRemoteAddr(), 
                        UserEvent.USER_LOGGED_OUT, this, null));
                    
                    //Disable authenticate button, because the user explicitly wanted to logout. 
                    bShowAuthNButton = false;
                    
                    error = session.getState();
                    
                    //logout finished
                    session.expire();
                    session.persist();
                    
                    break;
                }
                default:
                {
                    error = session.getState();

                    _eventLogger.info(new UserEventLogItem(session, 
                        servletRequest.getRemoteAddr(), 
                        UserEvent.INTERNAL_ERROR, this, "invalid state"));
                    
                    //session contains error, so can be removed.
                    session.expire();
                    session.persist();
                }
            }
        }
        
        forwardToIndex(servletRequest, servletResponse, error, warnings, 
            bShowAuthNButton, session);
    }
    
    private void processLogout(HttpServletRequest servletRequest, 
        HttpServletResponse servletResponse, ISession session) 
        throws OAException
    {
        try
        {
            String sTGTCookie = _cookieTool.getCookieValue(
                WebSSOServlet.TGT_COOKIE_NAME, servletRequest);
            if(sTGTCookie == null)
            {
                _logger.debug("No TGT cookie found, user already loggedout");
                
                if (session != null)
                {
                    session.expire();
                    session.persist();
                }
                
                processDefault(servletRequest, servletResponse, null);
                return;
            }
            
            String sServletPath = servletRequest.getServletPath();
            
            if (session == null)
            {
                String sRequestURL = _sRedirectURL;
                if (sRequestURL == null)
                {
                    sRequestURL = servletRequest.getRequestURL().toString();
                    if (sRequestURL.endsWith("/"))
                        sRequestURL = sRequestURL.substring(0, sRequestURL.length() - 1);
                    
                    if (sRequestURL.endsWith(PROFILE_ID + "/" + TARGET_LOGOUT))
                        sRequestURL = sRequestURL.substring(0, sRequestURL.length() - TARGET_LOGOUT.length());
                }
                
                session = _sessionFactory.createSession(_sUserPageRequestorId);
                session.persist();//resist for creating the session id
                
                StringBuffer sbProfileURL = new StringBuffer(sRequestURL);
                if (!sRequestURL.endsWith("/"))
                    sbProfileURL.append("/");
                sbProfileURL.append("?");
                sbProfileURL.append(ISession.ID_NAME);
                sbProfileURL.append("=");
                sbProfileURL.append(session.getId());
                session.setProfileURL(sbProfileURL.toString());
            }
            
            _logger.debug("Starting logout");
            
            session.persist();//update session; also to increase lifetime
            
            servletRequest.setAttribute(ISession.ID_NAME, session);
            
            StringBuffer sbForward = new StringBuffer(sServletPath);
            if (!sServletPath.endsWith("/"))
                sbForward.append("/");
            sbForward.append(LogoutProfile.PROFILE_ID);
            
            RequestDispatcher oDispatcher = servletRequest.getRequestDispatcher(
                sbForward.toString());
            if(oDispatcher == null)
            {
                _logger.warn(
                    "There is no requestor dispatcher supported with name: " 
                    + sbForward.toString());                    
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            oDispatcher.forward(servletRequest, servletResponse);
        }
        catch(OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during logout", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private void processAuthN(HttpServletRequest servletRequest, 
        HttpServletResponse servletResponse, ISession session) 
        throws OAException
    {
        try
        {
            if (session != null)
            {//user should not be here, show default page instead
                processDefault(servletRequest, servletResponse, session);
            }
            else
            {
                String sRequestURL = _sRedirectURL;
                if (sRequestURL == null)
                {
                    sRequestURL = servletRequest.getRequestURL().toString();
                    if (sRequestURL.endsWith("/"))
                        sRequestURL = sRequestURL.substring(0, sRequestURL.length() - 1);
                    
                    if (sRequestURL.endsWith(PROFILE_ID + "/" + TARGET_AUTHN))
                        sRequestURL = sRequestURL.substring(0, sRequestURL.length() - TARGET_AUTHN.length());
                }
                
                session = _sessionFactory.createSession(_sUserPageRequestorId);
                session.persist();//resist for creating the session id
                
                StringBuffer sbProfileURL = new StringBuffer(sRequestURL);
                if (!sRequestURL.endsWith("/"))
                    sbProfileURL.append("/");
                sbProfileURL.append("?");
                sbProfileURL.append(ISession.ID_NAME);
                sbProfileURL.append("=");
                sbProfileURL.append(session.getId());
                session.setProfileURL(sbProfileURL.toString());
                
                //don't have to persist the session, because the target of the foward is the /sso
                
                servletRequest.setAttribute(ISession.ID_NAME, session);
    
                _logger.debug("Starting authentication");
                
                String sServletPath = servletRequest.getServletPath();
                
                RequestDispatcher oDispatcher = servletRequest.getRequestDispatcher(
                    sServletPath);
                if(oDispatcher == null)
                {
                    _logger.warn(
                        "There is no requestor dispatcher supported with name: " 
                        + sServletPath);                    
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                oDispatcher.forward(servletRequest, servletResponse);
            }
        }
        catch(OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during authentication", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    private UserInfo getUserInfo(ISession session, ITGT oTgt) throws OAException
    {
        List<IAuthenticationProfile> listAuthNProfiles = 
            new Vector<IAuthenticationProfile>();
        for (String sAuthNProfile: oTgt.getAuthNProfileIDs())
        {
            IAuthenticationProfile authNProfile = _authenticationProfileFactory.getProfile(sAuthNProfile);
            if (authNProfile != null)
                listAuthNProfiles.add(authNProfile);
        }
        
        //create requestor list with latest added requestor first
        Vector<IRequestor> vRequestors = new Vector<IRequestor>();
        List<String> listRequestorIDs = oTgt.getRequestorIDs();
        for (int i = (listRequestorIDs.size() - 1); i >= 0; i--)
        {
            String sRequestorID = listRequestorIDs.get(i);
            IRequestor oRequestor = _requestorPoolFactory.getRequestor(sRequestorID);
            if (oRequestor != null && !vRequestors.contains(oRequestor))
                vRequestors.add(oRequestor);
        }
        
        List<IAttribute> listAttributes = new Vector<IAttribute>();
        
        if (session != null)
        {
            IAttributes attributes = session.getUser().getAttributes();
            Enumeration<?> enumAttributeNames = attributes.getNames();
            while (enumAttributeNames.hasMoreElements())
            {
                String sName = (String)enumAttributeNames.nextElement();
                Object oValue = attributes.get(sName);
                listAttributes.add(new UserAttribute(sName, oValue));
            }
        }
        
        UserInfo info =  new UserInfo(oTgt, listAuthNProfiles, vRequestors, listAttributes);
        
        return info;
    }

    private void forwardToIndex(HttpServletRequest servletRequest, 
        HttpServletResponse servletResponse, Enum error, List<TGTEventError> warnings, 
            boolean bShowAuthNButton, ISession session) throws OAException
    {
        try
        {
            if (bShowAuthNButton)
            {
                IRequestor requestor = _requestorPoolFactory.getRequestor(_sUserPageRequestorId);
                if (requestor == null || !requestor.isEnabled())
                {
                    bShowAuthNButton = false;
                }
                else
                {
                    RequestorPool requestorPool = _requestorPoolFactory.getRequestorPool(_sUserPageRequestorId);
                    if (requestorPool == null || !requestorPool.isEnabled())
                    {
                        bShowAuthNButton = false;
                    }
                }
            }  
            
            if (session != null)
            {
                servletRequest.setAttribute(ISession.ID_NAME, session.getId());
            }
            
            if (bShowAuthNButton)
            {
                servletRequest.setAttribute(JSP_AUTHN_ENABLED, bShowAuthNButton);
            }
            
            if (error != null)
            {
                servletRequest.setAttribute(UserException.USEREVENT_NAME, error);
            }
            
            if (warnings != null)
            {
                servletRequest.setAttribute(
                    DetailedUserException.DETAILS_NAME, warnings);
            }
            
            //Show user info
            //Set server info as attribute
            servletRequest.setAttribute(Server.SERVER_ATTRIBUTE_NAME, 
                Engine.getInstance().getServer());
            //Forward to page                
            RequestDispatcher oDispatcher = 
                servletRequest.getRequestDispatcher(_sJSPUserIndex); 
            if(oDispatcher != null)
                oDispatcher.forward(servletRequest, servletResponse);
            else
            {
                _logger.fatal("Forward request not supported");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        catch(OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during jsp forward", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private boolean verifyRequestorEnabled(ITGT tgt) throws OAException
    {
        RequestorPool requestorpool = _requestorPoolFactory.getRequestorPool(_sUserPageRequestorId);
        if (requestorpool == null)
        {
            _logger.debug("Requestor not available in a requestorpool: " + _sUserPageRequestorId);
            return false;
        }
        if (!requestorpool.isEnabled())
        {
            _logger.debug("Requestorpool disabled: " + requestorpool.getID());
            return false;
        }
        
        IRequestor requestor = _requestorPoolFactory.getRequestor(_sUserPageRequestorId);
        if (requestor == null)
        {
            _logger.debug("Requestor not available: " + _sUserPageRequestorId);
            return false;
        }
        else if (!requestor.isEnabled())
        {
            _logger.debug("Requestor disabled: " + _sUserPageRequestorId);
            return false;
        }
        
        List<String> listAuthNPoolProfiles = requestorpool.getAuthenticationProfileIDs();
        if (listAuthNPoolProfiles.size() == 0)
        {
            _logger.debug("Requestorpool doesn't contains authN profiles: " + requestorpool.getID());
            return false;
        }
        
        boolean bAuthNProfileAvailable = false;
        List<String> listAuthNTGTProfiles = tgt.getAuthNProfileIDs();
        for (String authNProfileIDs: listAuthNTGTProfiles)
        {
            if (listAuthNPoolProfiles.contains(authNProfileIDs))
            {
                bAuthNProfileAvailable = true;
                break;
            }
        }
        
        if (!bAuthNProfileAvailable)
        {
            StringBuffer sbDebug = new StringBuffer("Requestorpool (");
            sbDebug.append(requestorpool.getID());
            sbDebug.append(") doesn't have any authN Profiles available that are available in TGT: ");
            sbDebug.append(tgt.getId());
            _logger.debug(sbDebug.toString());
        }
                
        return bAuthNProfileAvailable;
    }
}
