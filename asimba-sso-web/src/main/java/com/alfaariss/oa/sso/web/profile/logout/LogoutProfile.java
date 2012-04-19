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
package com.alfaariss.oa.sso.web.profile.logout;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.IService;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.api.sso.ISSOProfile;
import com.alfaariss.oa.api.sso.logout.IASLogout;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.ITGTListener;
import com.alfaariss.oa.api.tgt.TGTEventError;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.sso.authentication.web.AuthenticationManager;
import com.alfaariss.oa.sso.authentication.web.IWebAuthenticationMethod;
import com.alfaariss.oa.sso.web.WebSSOServlet;
import com.alfaariss.oa.util.logging.SystemLogItem;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.validation.SessionValidator;
import com.alfaariss.oa.util.validation.TGTValidator;
import com.alfaariss.oa.util.web.CookieTool;
import com.alfaariss.oa.util.web.HttpUtils;

/**
 * Single Logout profile.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class LogoutProfile implements ISSOProfile, IService, IAuthority
{
    /** Profile ID: logout */
    public final static String PROFILE_ID = "logout";
    
    private final static String AUTHORITY_NAME = "LogoutProfile";
    
    private final static String SESSION_CURRENT_METHOD = "CURRENT_LOGOUT_METHOD";
    private final static String JSP_LOGOUT_STATE = "logoutState";
    
    private final static String TARGET_LOGOUT_FORCE = "force";
    private final static String TARGET_LOGOUT_STATE = "state";
    
    private final static String DEFAULT_JSP_LOGOUT = "/ui/sso/logout/logout.jsp";
    private final static String DEFAULT_JSP_CONFIRM = "/ui/sso/logout/confirm.jsp";
    
    private final static String PROPERTY_LOGOUT_CONFIRMATION = ".confirmation";
    
    private static Log _logger;
    private static Log _eventLogger;
    
    private AuthenticationManager _authenticationManager;
    private ITGTFactory<?> _tgtFactory;
    private ISessionFactory<?> _sessionFactory;
    private CookieTool _cookieTool;
    private Map<String, IASLogout> _mapLogoutMethods;
    private String _sMyOrganizationID;
    private String _sJSPUserLogout;
    private ITGTAliasStore _aliasStoreSP;
    private IRequestorPoolFactory _requestorPoolFactory;
    private boolean _bShowConfirmation;
    private String _sJSPConfirmation;

    /**
     * Constructor.
     * @param authenticationManager The authentication manager.
     */
    public LogoutProfile(AuthenticationManager authenticationManager)
    {
        _logger = LogFactory.getLog(LogoutProfile.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
        _mapLogoutMethods = null;
        _sJSPUserLogout = null;
        _authenticationManager = authenticationManager;
        _bShowConfirmation = false;
        _sJSPConfirmation = null;
    }
    
    /**
     * @see com.alfaariss.oa.api.sso.ISSOProfile#destroy()
     */
    public void destroy()
    {
        if (_mapLogoutMethods != null)
        {
            _mapLogoutMethods.clear();
        }
        _sJSPUserLogout = null;
        _sJSPConfirmation = null;
        _bShowConfirmation = false;
    }

    /**
     * @see ISSOProfile#getID()
     */
    public String getID()
    {
        return PROFILE_ID;
    }

    /**
     * @param eSpecific is always supplied as NULL
     * @see ISSOProfile#init(javax.servlet.ServletContext, 
     *  IConfigurationManager, org.w3c.dom.Element, org.w3c.dom.Element)
     */
    public void init(ServletContext context,
        IConfigurationManager configurationManager, Element eParent, 
        Element eSpecific) throws OAException
    {
        Engine engine = Engine.getInstance();
        _tgtFactory = engine.getTGTFactory();
        _sessionFactory = engine.getSessionFactory();
        _aliasStoreSP = _tgtFactory.getAliasStoreSP();
        _sMyOrganizationID = engine.getServer().getOrganization().getID();
        _requestorPoolFactory = engine.getRequestorPoolFactory();
        _cookieTool = new CookieTool(configurationManager, eParent);
        
        Element eLogout = configurationManager.getSection(eParent, "logout");
        if (eLogout == null)
        {
            _logger.warn("No optional 'logout' section available in configuration, using defaults");
            _sJSPUserLogout = DEFAULT_JSP_LOGOUT;
            _bShowConfirmation = false;
            _sJSPConfirmation = DEFAULT_JSP_CONFIRM;
        }
        else
        {
            readConfig(configurationManager, eLogout);
        }
        
        _mapLogoutMethods = loadLogoutMethods(_authenticationManager.getAuthenticationMethods());
        
        _logger.info("Started Logout Profile: " + PROFILE_ID);
    }

    /**
     * @see com.alfaariss.oa.api.IService#service(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public void service(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) throws OAException
    {
        try
        {
            //Disable caching
            HttpUtils.setDisableCachingHttpHeaders(servletRequest, servletResponse);     
            
            ISession session = (ISession)servletRequest.getAttribute(
                ISession.ID_NAME); 
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
                else
                    _logger.debug("No session attribute and no session id supplied in request");
            }
            
            String sTarget = resolveTarget(servletRequest);
            if (sTarget != null)
            {
                if (sTarget.equalsIgnoreCase(TARGET_LOGOUT_STATE))
                {
                    _logger.debug("Performing 'logout state' request");
                    processLogoutState(servletResponse, session);
                    return;
                }
                else if (sTarget.equalsIgnoreCase(TARGET_LOGOUT_FORCE))
                {
                    _logger.debug("Performing 'forced logout' request sent from IP: " 
                        + servletRequest.getRemoteAddr());
                    processForceLogout(servletRequest, servletResponse, session);
                    return;
                }
            }
            
            if (session == null)
            {
                _logger.debug("No valid session found");   
                throw new UserException(UserEvent.REQUEST_INVALID);
            }
            
            _logger.debug("Performing 'logout' request sent from IP: " 
                + servletRequest.getRemoteAddr());
            
            switch (session.getState())
            {
                case USER_LOGOUT_IN_PROGRESS:
                {//logout at remote authn not finished yet
                    finishFederativeLogout(servletRequest, servletResponse, session);
                    break;
                }
                case USER_LOGOUT_FAILED:
                case USER_LOGOUT_PARTIAL:
                {//already failed, only remove what can be removed
                    processForceLogout(servletRequest, servletResponse, session);
                    break;
                }
                case USER_LOGOUT_SUCCESS:
                {//remote logout finished, do local logout
                    processLocalLogout(servletRequest, servletResponse, session, null);
                    break;
                }
                case USER_CANCELLED:
                {
                    _logger.debug(new SystemLogItem(
                        session.getId(), SystemErrors.OK, 
                        "Redirect back to Profile" ));                                     
                    servletResponse.sendRedirect(session.getProfileURL());
                    break;  
                }
                default:
                {//check what needs to be done
                    processDefault(servletRequest, servletResponse, session);
                }
            }
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
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not perform logout request", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * @see com.alfaariss.oa.api.logging.IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME;
    }
    
    private void processDefault(HttpServletRequest servletRequest, 
        HttpServletResponse servletResponse, ISession session) 
        throws OAException, UserException
    {
        try
        {
            _logger.debug("Start logout");
            
            String sTGTID = _cookieTool.getCookieValue(
                    WebSSOServlet.TGT_COOKIE_NAME, servletRequest);
                
            if (sTGTID == null)
            {
                _logger.debug("No TGT cookie found");                
                throw new UserException(UserEvent.REQUEST_INVALID);                
            }
            
            if (sTGTID != null && !TGTValidator.validateDefaultTGTId(sTGTID))
            {
                _logger.debug("Invalid TGT ID in cookie: " + sTGTID);
                throw new UserException(UserEvent.REQUEST_INVALID);       
            }
                
            ITGT tgt = _tgtFactory.retrieve(sTGTID);
            if (tgt == null || tgt.isExpired())
            {
                session.setState(SessionState.USER_LOGOUT_PARTIAL);
                //remove cookie and perform redirect to profile
                processForceLogout(servletRequest, servletResponse, session);
            }
            else
            {
                //DD remove aliasses for requestor id from TGT, so requestor logout will not be triggered for this supplied requestor.
                if (_aliasStoreSP != null)
                    _aliasStoreSP.removeAll(session.getRequestorId(), tgt.getId());
                
                //DD remove requestor from TGT, because the user is now logged out at this requestor.
                tgt.removeRequestorID(session.getRequestorId());
                
                tgt.persist();
                
                session.setTGTId(sTGTID);
                
                IUser user = tgt.getUser();
                session.setUser(user);
                
                if (mustShowConfirmation(servletRequest, session, tgt))
                {
                    processConfirmation(servletRequest, servletResponse, tgt, session);
                    return;
                }
                
                IASLogout asLogout = null;
                if (_mapLogoutMethods != null)
                {
                    for (IASLogout method: _mapLogoutMethods.values())
                    {
                        if (method.canLogout(tgt))
                        {
                            asLogout = method;
                            break;
                        }
                    }
                }
                
                if (asLogout != null && !_sMyOrganizationID.equals(user.getOrganization()))
                {
                    session.getAttributes().put(this.getClass(), 
                        SESSION_CURRENT_METHOD, asLogout.getID());
                  
                    session.setState(SessionState.USER_LOGOUT_IN_PROGRESS);
                    
                    _logger.debug("do federative logout");
                    switch (asLogout.logout(servletRequest, servletResponse, tgt, session))
                    {
                        case USER_LOGOUT_IN_PROGRESS:
                        {
                            //do nothing, process not ended yet.
                            break;
                        }
                        case USER_LOGGED_OUT:
                        {
                            session.setState(SessionState.USER_LOGOUT_SUCCESS);
                            processLocalLogout(servletRequest, servletResponse, session, tgt);
                            break;
                        }
                        default:
                        {//all errors
                            processForceLogout(servletRequest, servletResponse, session);
                        }
                    }
                }
                else
                {
                    //DD No sLogout.logout(...) when no logout method is found and user organization is not the local idp (the remote organization is responsible for the logout)
                    //No session.persist() needed when forwarding to sso servlet.
                    processLocalLogout(servletRequest, servletResponse, session, tgt);
                }
            }
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error while performing the default process", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private void finishFederativeLogout(HttpServletRequest servletRequest, 
        HttpServletResponse servletResponse, ISession session) 
        throws OAException, UserException
    {
        try
        {
            _logger.debug("finish federative logout");
            
            String sTGTID = session.getTGTId();
            if (sTGTID == null)
            {
                _logger.debug("No TGT ID found in session");                
                throw new UserException(UserEvent.REQUEST_INVALID);
            }
            
            ITGT tgt = _tgtFactory.retrieve(sTGTID);
            if (tgt == null || tgt.isExpired())
            {
                _logger.debug("No TGT available with id: " + sTGTID);
                session.setState(SessionState.USER_LOGOUT_PARTIAL);
                //remove cookie and perform redirect to profile
                processForceLogout(servletRequest, servletResponse, session);
            }
            else
            {
                String sLogoutMethodID = (String)session.getAttributes().get(this.getClass(), 
                    SESSION_CURRENT_METHOD);
                if (sLogoutMethodID == null)
                {
                    _logger.debug("Required session attribute not available: " + SESSION_CURRENT_METHOD);                
                    throw new UserException(UserEvent.REQUEST_INVALID);
                }
                
                IASLogout asLogout = _mapLogoutMethods.get(sLogoutMethodID);
                if (asLogout == null)
                {
                    _logger.debug("No method found: " + sLogoutMethodID);                
                    throw new UserException(UserEvent.REQUEST_INVALID);
                }
                
                _logger.debug("proceed federative logout");
                switch (asLogout.logout(servletRequest, servletResponse, tgt, session))
                {
                    case USER_LOGOUT_IN_PROGRESS:
                    {
                        //do nothing, process not ended yet.
                        break;
                    }
                    case USER_LOGGED_OUT:
                    {
                        session.setState(SessionState.USER_LOGOUT_SUCCESS);
                        processLocalLogout(servletRequest, servletResponse, session, tgt);
                        break;
                    }
                    default:
                    {//all errors
                        processForceLogout(servletRequest, servletResponse, session);
                    }
                }
            }
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error while finishing federative logout", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Starts the logout process at the current (local) IDP, by executing logout events.
     * <br>
     * Call can only be initiated by a requestor (with session).
     */
    private void processLocalLogout(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse, ISession session, ITGT tgt) 
        throws OAException
    {
        _logger.debug("Start Logout at local IDP (only TGT Events)");
        
        try
        {
            if (session == null)
            {
                //No session, so the request is not initiated by any requestor (userpage or protocol profile)
                _logger.debug("No session available");                
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            String  sTGTID = session.getTGTId();
            if (sTGTID == null)
            {
                sTGTID = _cookieTool.getCookieValue(
                    WebSSOServlet.TGT_COOKIE_NAME, servletRequest);
                
                if (sTGTID == null)
                {
                    _logger.debug("No TGT ID available");                
                    throw new UserException(UserEvent.REQUEST_INVALID);                
                }
                
                if (sTGTID != null && !TGTValidator.validateDefaultTGTId(sTGTID))
                {
                    _logger.debug("Invalid TGT ID in cookie: " + sTGTID);
                    throw new UserException(UserEvent.REQUEST_INVALID);       
                }
                
                session.setTGTId(sTGTID);
            }
            
            SessionState state = session.getState();
            LogoutState logoutState = null;
            if (state != SessionState.USER_LOGOUT_IN_PROGRESS)
            {
                session.setState(SessionState.USER_LOGOUT_IN_PROGRESS);
                
                if (tgt == null)
                {
                    tgt = _tgtFactory.retrieve(sTGTID);
                    if(tgt == null || tgt.isExpired()) //TGT valid
                    {
                        _logger.debug("TGT already expired: " + sTGTID);                
                        throw new UserException(UserEvent.REQUEST_INVALID);
                    }
                }
                
                logoutState = startListeners(tgt, session, servletRequest);
            }
            else
            {
                //session must be persisted before showing a JSP
                session.persist();
            }
            
            if (logoutState != null && logoutState.isFinished())
                processForceLogout(servletRequest, servletResponse, session);
            else
                showLogoutJSP(servletRequest, servletResponse, 
                    SessionState.USER_LOGOUT_IN_PROGRESS, session.getId(), null);
        }
        catch(UserException e)
        {
            session.setState(SessionState.USER_LOGOUT_FAILED);
            
            _eventLogger.info(new UserEventLogItem(session, 
                servletRequest.getRemoteAddr(), 
                UserEvent.INTERNAL_ERROR, this, null));
            
            processForceLogout(servletRequest, servletResponse, session);
        }
        catch(OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during logout processing", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Removes the TGT, TGT cookie and reports back to the initiator.
     * <br>
     * Call can be initiated by a user (without session) or a requestor (with session).
     */
    @SuppressWarnings("unchecked")
    private void processForceLogout(HttpServletRequest servletRequest, 
        HttpServletResponse servletResponse, ISession session) 
        throws OAException
    {
        try
        {
            _logger.debug("Perform Forced Logout (remove the TGT)");
            
            //backup session state, used as result no session is available
            SessionState sessionStateBackup = SessionState.USER_LOGOUT_FAILED;
                        
            String sTGTID = null;
            if (session != null)
            {
                sTGTID = session.getTGTId();
            }
            
            String sTGTCookie = _cookieTool.getCookieValue(
                WebSSOServlet.TGT_COOKIE_NAME, servletRequest);
            if (sTGTCookie != null)
            {//remove TGT cookie
                _cookieTool.removeCookie(WebSSOServlet.TGT_COOKIE_NAME, 
                    servletRequest, servletResponse);
                _logger.debug("TGT cookie removed");
                
                sessionStateBackup = SessionState.USER_LOGOUT_PARTIAL;
            }
            
            if (sTGTID == null)
            {
                sTGTID = sTGTCookie;
                if (sTGTID != null && !TGTValidator.validateDefaultTGTId(sTGTID))
                {
                    _logger.debug("Not using invalid TGT ID resolved from cookie: " + sTGTID);
                    sTGTID = null;
                }
            }
                
            if (sTGTID != null) //TGT Cookie found
            {//remove TGT
                ITGT tgt = _tgtFactory.retrieve(sTGTID);
                if(tgt != null)
                { 
                    if (!tgt.isExpired()) //TGT valid
                        tgt.expire();
                    
                    try
                    {
                        if (session != null)
                        {
                            //events are already performed by processLogout()
                            tgt.persistPassingListenerEvent();
                        }
                        else
                        {
                            //persist should also perform events
                            tgt.persist();
                            
                            sessionStateBackup = SessionState.USER_LOGOUT_PARTIAL;
                        }
                    }
                    catch (PersistenceException e)
                    {
                        if (session != null)
                            session.setState(SessionState.USER_LOGOUT_FAILED);
                    }
                    
                    _logger.debug("TGT removed");
                }
            }
            
            if (session == null)
            {
                showLogoutJSP(servletRequest, servletResponse, sessionStateBackup, null, null);
            }
            else
            {
                //logout was interrupted, so logout is failed
                if (session.getState() == SessionState.USER_LOGOUT_IN_PROGRESS)
                    session.setState(SessionState.USER_LOGOUT_FAILED);
                
                //TGT is now removed, so remove TGT ID from the session if available
                session.setTGTId(null);
                session.persist();
                
                if (session.getState() != SessionState.USER_LOGOUT_SUCCESS)
                {
                    List<TGTEventError> warnings = new Vector<TGTEventError>();
                    ISessionAttributes sessionAttributes = session.getAttributes();
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
                    
                    showLogoutJSP(servletRequest, servletResponse, session.getState(), session.getId(), warnings);
                }
                else
                {   
                    String sRedirect = session.getProfileURL();
                    if (sRedirect == null)
                    {
                        _logger.warn("No redirect to profile URL available in session with id: " 
                            + session.getId());
                        throw new OAException (SystemErrors.ERROR_INTERNAL);
                    }
                    
                    _logger.debug("Logout finished for TGT with id: " + sTGTID);
                    _logger.debug("Redirecting user back to profile URL: " + sRedirect);
                    
                    servletResponse.sendRedirect(sRedirect);
                }
            }
        }
        catch(OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during forced logout", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private void processLogoutState(HttpServletResponse servletResponse, 
        ISession session) throws OAException
    {
        _logger.debug("Logout - Perform State Request");
        try
        {   
            servletResponse.setContentType("text/plain");
            
            if (session == null)
            {
                _logger.debug("no session");
                servletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
            else
            {
                switch (session.getState())
                {
                    case USER_LOGOUT_FAILED:
                    case USER_LOGOUT_PARTIAL:
                    case USER_LOGOUT_SUCCESS:
                    {
                        _logger.debug("finished");
                        servletResponse.sendError(HttpServletResponse.SC_OK);
                        break;
                    }
                    default:
                    {
                        _logger.debug("in progress");
                        servletResponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                    }
                }
            }
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during logout state resolving", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private void showConfirmJSP(HttpServletRequest servletRequest, 
        HttpServletResponse servletResponse, ISession session,
        List<IRequestor> listRequestors, IRequestor requestor) 
        throws OAException
    {
        try
        {
            servletRequest.setAttribute(ISession.ID_NAME, session.getId());
            servletRequest.setAttribute("requestors", listRequestors);
            servletRequest.setAttribute("requestor", requestor);
            servletRequest.setAttribute("user", session.getUser());
            
            //Set server info as attribute
            servletRequest.setAttribute(Server.SERVER_ATTRIBUTE_NAME, 
                Engine.getInstance().getServer());
            //Forward to page                
            RequestDispatcher oDispatcher = 
                servletRequest.getRequestDispatcher(_sJSPConfirmation); 
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
    
    private void showLogoutJSP(HttpServletRequest servletRequest, 
        HttpServletResponse servletResponse, SessionState state, 
        String sessionID, List<TGTEventError> warnings) throws OAException
    {
        try
        {
            if (sessionID != null)
                servletRequest.setAttribute(ISession.ID_NAME, sessionID);
            
            if (state != null)
                servletRequest.setAttribute(JSP_LOGOUT_STATE, state);
            
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
                servletRequest.getRequestDispatcher(_sJSPUserLogout); 
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
            _logger.fatal("Internal error during jsp forward to logout page", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private boolean mustShowConfirmation(HttpServletRequest servletRequest, 
        ISession session, ITGT tgt) throws OAException
    {
        if (_sJSPConfirmation == null)
            return false;
        
        if (servletRequest.getParameter("confirm") != null)
            return false;
        
        if (tgt.getRequestorIDs().size() < 1)
        {//user will only be loggedout at the requestor that initiated the logout
            return false;
        }
        
        String requestorID = session.getRequestorId();
        IRequestor requestor = _requestorPoolFactory.getRequestor(requestorID);
        if (requestor != null)
        {
            String sConfirm = (String)requestor.getProperty(PROFILE_ID + PROPERTY_LOGOUT_CONFIRMATION);
            if (sConfirm != null)
            {
                if (sConfirm.equalsIgnoreCase("TRUE"))
                    return true;
                else if (sConfirm.equalsIgnoreCase("FALSE"))
                    return false;
                else
                {
                    StringBuffer sbDebug = new StringBuffer("Invalid property '");
                    sbDebug.append(PROFILE_ID);
                    sbDebug.append(PROPERTY_LOGOUT_CONFIRMATION);
                    sbDebug.append("' found for requestor '");
                    sbDebug.append(requestorID);
                    sbDebug.append("': ");
                    sbDebug.append(sConfirm);
                    _logger.debug(sbDebug.toString());
                }   
            }
            else
                _logger.debug("No (optional) requestor specific logout confirmation property found for requestor with ID: " + requestorID);
            
            RequestorPool pool = _requestorPoolFactory.getRequestorPool(requestorID);
            if (pool != null)
            {
                String sPoolConfirm = (String)pool.getProperty(PROFILE_ID + PROPERTY_LOGOUT_CONFIRMATION);
                if (sPoolConfirm != null)
                {
                    if (sPoolConfirm.equalsIgnoreCase("TRUE"))
                        return true;
                    else if (sPoolConfirm.equalsIgnoreCase("FALSE"))
                        return false;
                    else
                    {
                        StringBuffer sbDebug = new StringBuffer("Invalid property '");
                        sbDebug.append(PROFILE_ID);
                        sbDebug.append(PROPERTY_LOGOUT_CONFIRMATION);
                        sbDebug.append("' found for requestorpool '");
                        sbDebug.append(pool.getID());
                        sbDebug.append("': ");
                        sbDebug.append(sPoolConfirm);
                        _logger.debug(sbDebug.toString());
                    }  
                }
                else
                    _logger.debug("No (optional) requestorpool specific logout confirmation property found for requestorpool with ID: " + pool.getID());
            }
        }
        
        return _bShowConfirmation;
    }
    
    private void processConfirmation(HttpServletRequest servletRequest, 
        HttpServletResponse servletResponse, ITGT tgt, ISession session)
        throws OAException
    {
        //create requestor list with latest added requestor first
        Vector<IRequestor> vRequestors = new Vector<IRequestor>();
        List<String> listRequestorIDs = tgt.getRequestorIDs();
        for (int i = (listRequestorIDs.size() - 1); i >= 0; i--)
        {
            String sRequestorID = listRequestorIDs.get(i);
            IRequestor oRequestor = _requestorPoolFactory.getRequestor(sRequestorID);
            if (oRequestor != null && !vRequestors.contains(oRequestor))
                vRequestors.add(oRequestor);
        }
        
        session.persist();
        
        IRequestor requestor =  _requestorPoolFactory.getRequestor(session.getRequestorId());
        
        showConfirmJSP(servletRequest, servletResponse, session, vRequestors, requestor);
    }
    
    private LogoutState startListeners(ITGT tgt, ISession session, 
        HttpServletRequest servletRequest) throws OAException
    {
        List<Thread> listThreads = new Vector<Thread>();
        //create threads
        LogoutState state = new LogoutState(_sessionFactory, session.getId());
        
        int iIndex = 0;
        for (ITGTListener listener: _tgtFactory.getListeners())
        {
            iIndex++;
            
            StringBuffer sbRunnableName = new StringBuffer(session.getId());
            sbRunnableName.append("_");
            sbRunnableName.append(iIndex);
            LogoutRunnable runnable = new LogoutRunnable(listener, tgt, state, sbRunnableName.toString());
            Thread tLogout = new Thread(runnable);
            
            StringBuffer sbThreadname = new StringBuffer("Logout (" );
            sbThreadname.append(sbRunnableName.toString());
            sbThreadname.append(") - ");
            sbThreadname.append(tLogout.getName());
            tLogout.setName(sbThreadname.toString());
            listThreads.add(tLogout);
        }
        
        session.persist();
        
        _eventLogger.info(new UserEventLogItem(session, 
            servletRequest.getRemoteAddr(), 
            UserEvent.USER_LOGOUT_IN_PROGRESS, this, null));
        
        //start threads
        for (Thread thread: listThreads)
        {
            thread.start();
            _logger.debug("Started: " + thread.getName());
        }
        
        _logger.debug("Logout threads started");
        
        return state;
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
    
    private Map<String, IASLogout> loadLogoutMethods(
        Map<String, IWebAuthenticationMethod> mapAuthNMethods) throws OAException
    {
        Map<String, IASLogout> mapLogoutMethods = new HashMap<String, IASLogout>();
        try
        {
            for (IWebAuthenticationMethod method: mapAuthNMethods.values())
            {
                if (method.isEnabled())
                {
                    if (method instanceof IASLogout)
                    {
                        IASLogout aslogout = (IASLogout)method;
                        if (mapLogoutMethods.containsKey(aslogout.getID()))
                        {
                            _logger.info("Authentication method has not a unique id: " 
                                + aslogout.getID());
                        }
                        else
                        {
                            _logger.info("Found asynchronous logout method: " 
                                + aslogout.getID());
                            mapLogoutMethods.put(aslogout.getID(), aslogout);
                        }
                    }
                }
            }
        }
        catch(Exception e)
        {
            _logger.fatal("Could not load asynchronous logout methods", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return mapLogoutMethods;
    }
    
    private void readConfig(IConfigurationManager configurationManager, 
        Element config) throws OAException
    {
        Element eJSP = configurationManager.getSection(config, "jsp");
        if (eJSP == null)
        {
            _logger.warn("No optional 'jsp' parameter found in 'logout' section in configuration; using default");
            _sJSPUserLogout = DEFAULT_JSP_LOGOUT;
        }
        else
        {
            _sJSPUserLogout = configurationManager.getParam(eJSP, "path");
            if (_sJSPUserLogout == null)
            {
                _logger.error("No 'path' parameter found in 'jsp' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        _logger.info("Using logout jsp location: " + _sJSPUserLogout);
        
        _bShowConfirmation = false;
        _sJSPConfirmation = DEFAULT_JSP_CONFIRM;
        Element eConfirmation = configurationManager.getSection(config, "confirmation");
        if (eConfirmation == null)
        {
            _logger.warn("No optional 'confirmation' section found within 'logout' section in configuration; using defaults");
        }
        else
        {
            Element eConfirmationJSP = configurationManager.getSection(eConfirmation, "jsp");
            if (eConfirmationJSP == null)
            {
                _logger.warn("No optional 'jsp' parameter found in 'confirmation' section in logout confirmation configuration; using default");
                _sJSPConfirmation = DEFAULT_JSP_CONFIRM;
            }
            else
            {
                _sJSPConfirmation = configurationManager.getParam(eConfirmationJSP, "path");
                if (_sJSPConfirmation == null)
                {
                    _logger.error("No 'path' parameter found in 'jsp' section in logout confirmation configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            String sShow = configurationManager.getParam(eConfirmation, "show");
            if (sShow == null)
            {
                _logger.warn("No optional 'show' parameter found in 'confirmation' section in logout confirmation configuration; using default");
            }
            else
            {
                if (sShow.equalsIgnoreCase("TRUE"))
                    _bShowConfirmation = true;
                else if (!sShow.equalsIgnoreCase("FALSE"))
                {
                    _logger.error("Unknown value in 'show' configuration item: " 
                        + sShow);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
        }
        _logger.info("Using logout confirmation jsp location: " + _sJSPConfirmation);
        _logger.info("Default show logout confirmation: " + (_bShowConfirmation ? "enabled" : "disabled"));
    }
}
