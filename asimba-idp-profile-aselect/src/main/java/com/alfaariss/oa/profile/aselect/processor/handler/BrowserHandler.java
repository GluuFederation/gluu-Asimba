
/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
package com.alfaariss.oa.profile.aselect.processor.handler;

import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.List;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.DetailedUserException;
import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.profile.aselect.ASelectErrors;
import com.alfaariss.oa.profile.aselect.ASelectException;
import com.alfaariss.oa.profile.aselect.binding.IBinding;
import com.alfaariss.oa.profile.aselect.binding.IRequest;
import com.alfaariss.oa.profile.aselect.processor.ASelectProcessor;
import com.alfaariss.oa.util.ModifiedBase64;
import com.alfaariss.oa.util.logging.RequestorEventLogItem;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.validation.SessionValidator;


/**
 * The browser request handler.
 *
 * Processes requests from the user's browser.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class BrowserHandler implements IAuthority
{
    /** Alias type: aselect_credentials */
    public final static String ALIAS_TYPE_CREDENTIALS = "aselect_credentials";
        
    private final static String SSO_LOGOUT_URI = "logout";
    
    private final static String PROPERTY_LOCAL_ERROR_HANDLING = ".local_error_handling";
    private final static String PROPERTY_REDIRECT_PAGE = ".redirectreset";
    
    private Log _logger;
    private Log _eventLogger;
    
    private Server _server;
    private ISessionFactory _sessionFactory;
    private ITGTAliasStore _aliasStoreSPRole;
    private SecureRandom _oSecureRandom;
    private IRequestorPoolFactory _requestorPoolFactory;
    private String _sRedirectURL;
    private String _sWebSSOPath;
    private String _sWebSSOUrl;
    private String _sErrorJspPath;
    private boolean _bLocalErrorHandling;
    private String _sProfileID;
    private String _sRedirectJspPath;
    
    /**
     * Creates the object.
     *
     * @param sRedirectURL the full URL to this profile or <code>null</code> 
     * (for loadbalanced environments)
     * @param sWebSSOPath the relative path from the context to the WebSSO
     * @param sWebSSOUrl the full URL to the WebSSO
     * @param sErrorJspPath the relative path from the context to the jsp file 
     * that shows the errors
     * @param bLocalErrorHandling TRUE if errors during authentication must be 
     * showed in an error page
     * @param sProfileID The ID of the OA profile
     * @param sRedirectJspPath Redirect JSP page for resetting the browser 
     * redirect counter 
     * @throws OAException if creation fails
     */
    public BrowserHandler (String sRedirectURL, String sWebSSOPath, 
        String sWebSSOUrl, String sErrorJspPath, boolean bLocalErrorHandling,
        String sProfileID, String sRedirectJspPath) throws OAException
    {
        try
        {
            _logger = LogFactory.getLog(BrowserHandler.class);
            _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
            
            _sProfileID = sProfileID;
            
            Engine engine = Engine.getInstance();
            _server = engine.getServer();
            _sessionFactory = engine.getSessionFactory();
            
            ITGTFactory tgtFactory = engine.getTGTFactory();
            _aliasStoreSPRole = tgtFactory.getAliasStoreSP(); 
            if (_aliasStoreSPRole != null)
            {
                try
                {
                    _aliasStoreSPRole.isAlias(ALIAS_TYPE_CREDENTIALS, "test_sp", 
                        "test_alias");
                    _logger.info("TGT Factory supports SP Role alias storage; credentials will be stored as TGT alias of type: " 
                        + ALIAS_TYPE_CREDENTIALS);
                }
                catch (OAException e)
                {
                    _logger.info("TGT Factory has alias support, but doesn't support alias of type: " 
                        + ALIAS_TYPE_CREDENTIALS);
                }
            }   
            else
                _logger.info("TGT Factory doesn't support SP Role alias storage: credentials will not be stored as TGT alias");
                        
            CryptoManager oCryptoManager = engine.getCryptoManager();
            if (oCryptoManager == null)
            {
                _logger.error("No crypto manager available");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            _oSecureRandom = oCryptoManager.getSecureRandom();
            
            _sRedirectURL = sRedirectURL;
            _sWebSSOPath = sWebSSOPath;
            _sWebSSOUrl = sWebSSOUrl;
            _sErrorJspPath = sErrorJspPath;
            _bLocalErrorHandling = bLocalErrorHandling;
            _sRedirectJspPath = sRedirectJspPath;
            _requestorPoolFactory = engine.getRequestorPoolFactory();
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during object creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Processes the <code>request=login1</code> request.
     *
     * The request parameters that are supported:
     * <table border='1'>
     * <tr><th><i>parameter</i></th><th><i>value</i></th><th><i>optional?</i></th></tr>
     * <tr><td>request</td><td>login1</td><td>false</td></tr>
     * <tr><td>rid</td><td>[rid]</td><td>false</td></tr>
     * <tr><td>a-select-server</td><td>[a-select-server]</td><td>false</td></tr>
     * </table>
     * <br>
     * @param oServletRequest HTTP servlet request object
     * @param oServletResponse HTTP servlet response object
     * @param oBinding The binding object
     * @throws ASelectException if request handling failed
     */
    public void login1(HttpServletRequest oServletRequest, 
        HttpServletResponse oServletResponse, IBinding oBinding) throws ASelectException
    {
        ISession oSession = null;
        try
        {
            IRequest oRequest = oBinding.getRequest();
            
            String sASelectServer = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_ASELECTSERVER);
            if (sASelectServer == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_ASELECTSERVER);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            String sRID = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_RID);
            if (sRID == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_RID);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if(!SessionValidator.validateDefaultSessionId(sRID))
            {
                StringBuffer sbError = new StringBuffer("Invalid '");
                sbError.append(ASelectProcessor.PARAM_RID);
                sbError.append("' in request: ");
                sbError.append(sRID);
                _logger.debug(sbError.toString());
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            } 
            
            if (!_server.getID().equals(sASelectServer))
            {
                StringBuffer sbError = new StringBuffer(
                    "The Server ID doesn't correspond to the supplied '");
                sbError.append(ASelectProcessor.PARAM_ASELECTSERVER);
                sbError.append("' parameter: ");
                sbError.append(sASelectServer);
                _logger.debug(sbError.toString());
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_ID_MISMATCH);
            }
                        
            oSession = _sessionFactory.retrieve(sRID);
            if (oSession == null)
            {
                _logger.debug("No session found with id: " + sRID);
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if (oSession.isExpired())
            {
                StringBuffer sbError = new StringBuffer(
                    "Expired session with id '");
                sbError.append(sRID);
                sbError.append("' found in request sent from IP: ");
                sbError.append(oServletRequest.getRemoteAddr());
                _logger.debug(sbError.toString());
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
            }
                
            StringBuffer sbProfileURL = new StringBuffer();
            if (_sRedirectURL == null)
                sbProfileURL.append(oRequest.getRequestedURL());
            else
                sbProfileURL.append(_sRedirectURL);
            sbProfileURL.append("?");
            sbProfileURL.append(ASelectProcessor.PARAM_ASELECTSERVER);
            sbProfileURL.append("=");
            sbProfileURL.append(
                URLEncoder.encode(_server.getID(), ASelectProcessor.CHARSET));
            sbProfileURL.append("&");
            sbProfileURL.append(ASelectProcessor.PARAM_RID);
            sbProfileURL.append("=");
            sbProfileURL.append(URLEncoder.encode(sRID, ASelectProcessor.CHARSET));
            oSession.setProfileURL(sbProfileURL.toString());
            
            oServletRequest.setAttribute(ISession.ID_NAME, oSession);
            
            RequestDispatcher oDispatcher = oServletRequest.getRequestDispatcher(
                _sWebSSOPath);
            if(oDispatcher == null)
            {
                _logger.warn(
                    "There is no requestor dispatcher supported with name: " 
                    + _sWebSSOPath);                    
                throw new ASelectUserException(UserEvent.INTERNAL_ERROR,
                    ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            oDispatcher.forward(oServletRequest, oServletResponse);
        }
        catch (ASelectUserException e)
        {
            UserEvent event = e.getEvent();
            String sCode = e.getMessage();
            if (oSession != null)
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(),event, this,sCode));
            else
                _eventLogger.info(new UserEventLogItem(null, null, 
                    null,event, null, 
                    oServletRequest.getRemoteAddr(), null, this, sCode));
            
            showErrorPage(oServletRequest, oServletResponse, event, sCode, oSession);
        }
        catch (OAException e)
        {
            _eventLogger.info(new UserEventLogItem(null, null, null, 
                UserEvent.INTERNAL_ERROR, null, oServletRequest.getRemoteAddr(), 
                null, this, e.getMessage()));
            
            _logger.error("Exception occurred during 'login1' process", e);
            throw new ASelectException(e.getMessage());
        }
        catch (Exception e)
        {
            if (oSession != null)
                _eventLogger.info(new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), 
                    RequestorEvent.INTERNAL_ERROR, this, null));
            else
                _eventLogger.info(new RequestorEventLogItem(null, null, 
                    null,RequestorEvent.INTERNAL_ERROR, null, 
                    oServletRequest.getRemoteAddr(), null, this, null));
            
            _logger.fatal("Internal error during 'login1' process", e);
            throw new ASelectException(ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }
    
    /**
     * Handle the redirect sent by the WebSSO after authentication.
     *
     * Redirects the user to the application also if the user isn't authenticated.
     * @param oServletRequest HTTP servlet request object
     * @param oServletResponse HTTP servlet response object
     * @param oBinding The binding object
     * @throws ASelectException if request handling failed
     */
    public void authenticate(HttpServletRequest oServletRequest, 
        HttpServletResponse oServletResponse, IBinding oBinding) 
            throws ASelectException
    {
        ISession oSession = null;
        try
        {
            IRequest oRequest = oBinding.getRequest();
            
            String sASelectServer = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_ASELECTSERVER);
            if (sASelectServer == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_ASELECTSERVER);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            String sRID = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_RID);
            if (sRID == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_RID);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if(!SessionValidator.validateDefaultSessionId(sRID))
            {
                StringBuffer sbError = new StringBuffer("Invalid '");
                sbError.append(ASelectProcessor.PARAM_RID);
                sbError.append("' in request: ");
                sbError.append(sRID);
                _logger.debug(sbError.toString());
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            } 
            
            if (!_server.getID().equals(sASelectServer))
            {
                StringBuffer sbError = new StringBuffer(
                    "The Server ID doesn't correspond to the supplied '");
                sbError.append(ASelectProcessor.PARAM_ASELECTSERVER);
                sbError.append("' parameter: ");
                sbError.append(sASelectServer);
                _logger.debug(sbError.toString());
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_ID_MISMATCH);
            }
                        
            oSession = _sessionFactory.retrieve(sRID);
            if (oSession == null)
            {
                _logger.debug("No session found with id: " + sRID);
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if (oSession.isExpired())
            {
                StringBuffer sbError = new StringBuffer(
                    "Expired session with id '");
                sbError.append(sRID);
                sbError.append("' found in request sent from IP: ");
                sbError.append(oServletRequest.getRemoteAddr());
                _logger.debug(sbError.toString());
                
                throw new ASelectUserException(UserEvent.SESSION_EXPIRED,
                    ASelectErrors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
            }
            
            SessionState oUserState = oSession.getState();
            
            RequestorPool requestorPool = _requestorPoolFactory.getRequestorPool(oSession.getRequestorId());
                        
            if (doLocalErrorHandling(requestorPool) && !oUserState.equals(SessionState.AUTHN_OK))
            {
                switch (oUserState)
                {
                    case AUTHN_FAILED:
                    case PRE_AUTHZ_FAILED:
                    case POST_AUTHZ_FAILED:
                    case AUTHN_SELECTION_FAILED:
                    {
                        throw new ASelectException(
                            ASelectErrors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER); 
                    }
                    case USER_BLOCKED:
                    {
                        throw new ASelectException(
                            ASelectErrors.ERROR_USER_BLOCKED);
                    }
                    case USER_UNKNOWN:
                    {
                        throw new ASelectException(
                            ASelectErrors.ERROR_ASELECT_UDB_UNKNOWN_USER);
                    }
                    case USER_CANCELLED:
                    {
                        throw new ASelectException(
                            ASelectErrors.ERROR_ASELECT_SERVER_CANCEL);
                    }
                    case PASSIVE_FAILED:
                    {
                        throw new ASelectException(
                            ASelectErrors.ERROR_PASSIVE_FAILED);
                    }
                    default:
                    {
                        throw new ASelectException(
                            ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                    }
                }
            }
            
            ISessionAttributes oAttributes = oSession.getAttributes();

            String sRequestorUrl = (String)oAttributes.get(
                ASelectProcessor.class, ASelectProcessor.SESSION_REQUESTOR_URL);
            if(sRequestorUrl == null)
            {
                _logger.debug("No session attribute found with with name: " 
                    + ASelectProcessor.SESSION_REQUESTOR_URL);
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
                        
            byte[] baRandom = new byte[ASelectProcessor.CREDENTIALS_LENGTH];
            _oSecureRandom.nextBytes(baRandom);
            String sCredentials = new String(
                ModifiedBase64.encode(baRandom, ASelectProcessor.CHARSET));
            
            oAttributes.put(ASelectProcessor.class, 
                ASelectProcessor.SESSION_CREDENTIALS, sCredentials);
            
            if (_aliasStoreSPRole != null)
            {
                if (oSession.getTGTId() != null)
                {
                    _logger.debug("Setting TGT alias with name " + ALIAS_TYPE_CREDENTIALS);
                    _aliasStoreSPRole.putAlias(ALIAS_TYPE_CREDENTIALS,
                        oSession.getRequestorId(), oSession.getTGTId(), sCredentials);
                }
            }
            
            StringBuffer sbRedirect = new StringBuffer(sRequestorUrl);
            if (sRequestorUrl.indexOf("?") == -1)
                sbRedirect.append("?");
            else
                sbRedirect.append("&");
            
            sbRedirect.append(ASelectProcessor.PARAM_ASELECT_CREDENTIALS);
            sbRedirect.append("=");
            sbRedirect.append(
                URLEncoder.encode(sCredentials, ASelectProcessor.CHARSET));
            sbRedirect.append("&");
            sbRedirect.append(ASelectProcessor.PARAM_RID);
            sbRedirect.append("=");
            sbRedirect.append(
                URLEncoder.encode(sRID, ASelectProcessor.CHARSET));
            sbRedirect.append("&");
            sbRedirect.append(ASelectProcessor.PARAM_ASELECTSERVER);
            sbRedirect.append("=");
            sbRedirect.append(
                URLEncoder.encode(_server.getID(), ASelectProcessor.CHARSET));
            
            if(!oUserState.equals(SessionState.AUTHN_OK))
                _eventLogger.info(new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), 
                    RequestorEvent.AUTHN_FAILED, 
                    this, null));
            else
                _eventLogger.info(new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), 
                    RequestorEvent.AUTHN_SUCCESSFUL, 
                    this, null));
            
            oSession.persist();
            
            IRequestor requestor = _requestorPoolFactory.getRequestor(oSession.getRequestorId());
            if (doRedirectWithPage(requestor, requestorPool))
            {//use redirect page to reset browser redirect counter
                forwardToAutoRedirect(oServletRequest, oServletResponse, 
                    sbRedirect.toString(), requestor);
            }
            else
                oServletResponse.sendRedirect(sbRedirect.toString());
        }
        catch (ASelectUserException e)
        {
            UserEvent event = e.getEvent();
            String sCode = e.getMessage();
            if (oSession != null)
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(),event, this,sCode));
            else
                _eventLogger.info(new UserEventLogItem(null, null, 
                    null,event, null, oServletRequest.getRemoteAddr(), 
                    null, this, sCode));
            
            showErrorPage(oServletRequest, oServletResponse, event, sCode, oSession);
        }
        catch (ASelectException e)
        {          
            //Authentication failed
            if (oSession != null)
                _eventLogger.info(new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), RequestorEvent.AUTHN_FAILED, 
                    this, e.getMessage()));
            else
                _eventLogger.info(new RequestorEventLogItem(null, null, 
                    null,RequestorEvent.AUTHN_FAILED, null, 
                    oServletRequest.getRemoteAddr(), null, this, e.getMessage()));
            
            showErrorPage(oServletRequest, oServletResponse, null, 
                e.getMessage(), oSession);
        }       
        catch (OAException e)
        {
            _eventLogger.info(new UserEventLogItem(null, null, null, 
                UserEvent.INTERNAL_ERROR, null, oServletRequest.getRemoteAddr(), 
                null, this, e.getMessage()));
            
            _logger.error("Exception occurred during 'authenticate' process", e);
            throw new ASelectException(e.getMessage());
        }
        catch (Exception e)
        {
            if (oSession != null)
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                    this, "authentication finalization"));
            else
                _eventLogger.info(new UserEventLogItem(null, null, 
                    null, UserEvent.INTERNAL_ERROR, null, 
                    oServletRequest.getRemoteAddr(), null, this, 
                    "authentication finalization"));
            
            _logger.fatal(
                "Internal error during authenticate request process initiated by the Web SSO", e);
            throw new ASelectException(
                ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }
    
    /**
     * Handle the redirect sent by the application to show the user information page.
     * <br>
     * Redirects the user to the WebSSO.
     * @param oServletRequest HTTP servlet request object
     * @param oServletResponse HTTP servlet response object
     * @throws ASelectException if request handling failed
     */
    public void userinformation(HttpServletRequest oServletRequest, 
        HttpServletResponse oServletResponse)
        throws ASelectException
    {
        try
        {
            if (_sWebSSOUrl != null)
            {
                _logger.debug("Redirect to web sso: " + _sWebSSOUrl);
                try
                {
                    oServletResponse.sendRedirect(_sWebSSOUrl);
                }
                catch(Exception e)
                {
                    _eventLogger.info(new UserEventLogItem(null, null, null, 
                        UserEvent.INTERNAL_ERROR, null, oServletRequest.getRemoteAddr(), 
                        null, this, "user information"));
                    
                    _logger.fatal(
                        "Internal error during user information request process", e);
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                }
            }
            else
            {
                _logger.debug("Forward to web sso: " + _sWebSSOPath);
                RequestDispatcher oDispatcher = 
                    oServletRequest.getRequestDispatcher(_sWebSSOPath);
                if(oDispatcher == null)
                {
                    _eventLogger.info(new UserEventLogItem(null, null, null, 
                        UserEvent.INTERNAL_ERROR, null, oServletRequest.getRemoteAddr(), 
                        null, this, "user information"));
                    
                    _logger.warn(
                        "There is no requestor dispatcher supported with name: " 
                        + _sWebSSOPath);                    
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                }
                
                oDispatcher.forward(oServletRequest, oServletResponse);
            }
        }
        catch (ASelectException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _eventLogger.info(new UserEventLogItem(null, null, null, 
                UserEvent.INTERNAL_ERROR, null, oServletRequest.getRemoteAddr(), 
                null, this, "user information"));
            
            _logger.fatal(
                "Internal error during user information request process", e);
            throw new ASelectException(
                ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }
    
    /**
     * @see IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return ASelectProcessor.AUTHORITY_NAME;
    }
    
    /**
     * Process asynchronous logout results.
     *
     * @param oServletRequest HTTP servlet request object
     * @param oServletResponse HTTP servlet response object
     * @param oBinding The binding object
     * @throws ASelectException if request handling failed
     * @since 1.4
     */
    public void logout(HttpServletRequest oServletRequest, 
        HttpServletResponse oServletResponse, IBinding oBinding) 
        throws ASelectException
    {
        ISession session = null;
        try
        {
            IRequest oRequest = oBinding.getRequest();
            
            String sASelectServer = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_ASELECTSERVER);
            if (sASelectServer == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_ASELECTSERVER);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            String sRID = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_RID);
            if (sRID == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_RID);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if(!SessionValidator.validateDefaultSessionId(sRID))
            {
                StringBuffer sbError = new StringBuffer("Invalid '");
                sbError.append(ASelectProcessor.PARAM_RID);
                sbError.append("' in request: ");
                sbError.append(sRID);
                _logger.debug(sbError.toString());
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            } 
            
            if (!_server.getID().equals(sASelectServer))
            {
                StringBuffer sbError = new StringBuffer(
                    "The Server ID doesn't correspond to the supplied '");
                sbError.append(ASelectProcessor.PARAM_ASELECTSERVER);
                sbError.append("' parameter: ");
                sbError.append(sASelectServer);
                _logger.debug(sbError.toString());
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_ID_MISMATCH);
            }
                        
            session = _sessionFactory.retrieve(sRID);
            if (session == null)
            {
                _logger.debug("No session found with id: " + sRID);
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if (session.isExpired())
            {
                StringBuffer sbError = new StringBuffer(
                    "Expired session with id '");
                sbError.append(sRID);
                sbError.append("' found in request sent from IP: ");
                sbError.append(oServletRequest.getRemoteAddr());
                _logger.debug(sbError.toString());
                throw new ASelectUserException(UserEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
            }
            
            switch (session.getState())
            {
                case USER_LOGOUT_SUCCESS:
                {
                    String sRequestorURL = 
                        (String)session.getAttributes().get(ASelectProcessor.class, 
                            ASelectProcessor.SESSION_REQUESTOR_URL);
                    
                    _eventLogger.info(new UserEventLogItem(session, 
                        oServletRequest.getRemoteAddr(),
                        UserEvent.USER_LOGGED_OUT, this, null));
                    
                    _logger.debug("Logout succeeded, redirect user back to requestor: " 
                        + sRequestorURL);
                    
                    oServletResponse.sendRedirect(sRequestorURL);
                    break;
                }
                case USER_LOGOUT_PARTIAL:
                case USER_LOGOUT_FAILED:
                {
                    throw new ASelectUserException(UserEvent.USER_LOGOUT_FAILED, 
                        ASelectErrors.ERROR_LOGOUT_FAILED);
                }
                case USER_LOGOUT_IN_PROGRESS:
                {
                    oServletRequest.setAttribute(ISession.ID_NAME, session);
                    
                    StringBuffer sbForward = new StringBuffer(_sWebSSOPath);
                    if (!_sWebSSOPath.endsWith("/"))
                        sbForward.append("/");
                    sbForward.append(SSO_LOGOUT_URI);
                    
                    _logger.debug("Forwarding user to: " + sbForward.toString());
                    
                    RequestDispatcher oDispatcher = 
                        oServletRequest.getRequestDispatcher(sbForward.toString());
                    if(oDispatcher == null)
                    {
                        _logger.warn(
                            "There is no requestor dispatcher supported with name: " 
                            + sbForward.toString());                    
                        throw new ASelectUserException(UserEvent.INTERNAL_ERROR,
                            ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                    }
                    
                    oDispatcher.forward(oServletRequest, oServletResponse);
                    break;
                }
                default:
                {//forward user to start logout process
                    
                    StringBuffer sbProfileURL = new StringBuffer();
                    if (_sRedirectURL == null)
                        sbProfileURL.append(oRequest.getRequestedURL());
                    else
                        sbProfileURL.append(_sRedirectURL);
                    
                    sbProfileURL.append("?request=logout&");
                    sbProfileURL.append(ASelectProcessor.PARAM_ASELECTSERVER);
                    sbProfileURL.append("=");
                    sbProfileURL.append(
                        URLEncoder.encode(_server.getID(), ASelectProcessor.CHARSET));
                    sbProfileURL.append("&");
                    sbProfileURL.append(ASelectProcessor.PARAM_RID);
                    sbProfileURL.append("=");
                    sbProfileURL.append(URLEncoder.encode(sRID, ASelectProcessor.CHARSET));
                    session.setProfileURL(sbProfileURL.toString());
                                        
                    oServletRequest.setAttribute(ISession.ID_NAME, session);
                    
                    StringBuffer sbForward = new StringBuffer(_sWebSSOPath);
                    if (!_sWebSSOPath.endsWith("/"))
                        sbForward.append("/");
                    sbForward.append(SSO_LOGOUT_URI);
                    
                    _logger.debug("Forwarding user to: " + sbForward.toString());
                    
                    RequestDispatcher oDispatcher = 
                        oServletRequest.getRequestDispatcher(sbForward.toString());
                    if(oDispatcher == null)
                    {
                        _logger.warn(
                            "There is no requestor dispatcher supported with name: " 
                            + sbForward.toString());                    
                        throw new ASelectUserException(UserEvent.INTERNAL_ERROR,
                            ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                    }
                    
                    _eventLogger.info(new UserEventLogItem(session, 
                        oServletRequest.getRemoteAddr(),
                        UserEvent.USER_LOGOUT_IN_PROGRESS, this, null));
                    
                    oDispatcher.forward(oServletRequest, oServletResponse);
                }
            }
        }
        catch (ASelectUserException e)
        {
            UserEvent event = e.getEvent();
            String sCode = e.getMessage();
            if (session != null)
                _eventLogger.info(new UserEventLogItem(session, 
                    oServletRequest.getRemoteAddr(),event, this,sCode));
            else
                _eventLogger.info(new UserEventLogItem(null, null, 
                    null,event, null, 
                    oServletRequest.getRemoteAddr(), null, this, sCode));
            
            showErrorPage(oServletRequest, oServletResponse, event, sCode, session);
        }
        catch (OAException e)
        {
            _eventLogger.info(new UserEventLogItem(null, null, null, 
                UserEvent.INTERNAL_ERROR, null, oServletRequest.getRemoteAddr(), 
                null, this, e.getMessage()));
            
            _logger.error("Exception occurred during 'logout' process", e);
            throw new ASelectException(e.getMessage());
        }
        catch(Exception e)
        {
            _eventLogger.info(new UserEventLogItem(null, null, null, 
                UserEvent.INTERNAL_ERROR, null, oServletRequest.getRemoteAddr(), 
                null, this, "logout"));
            
            _logger.fatal(
                "Internal error during logout request process", e);
            throw new ASelectException(
                ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }

    //shows the error jsp
    private void showErrorPage(HttpServletRequest oServletRequest, 
        HttpServletResponse oServletResponse, UserEvent oEvent, String sCode, 
        ISession oSession) throws ASelectException
    {
        try
        {
            if(oEvent != null)
            {
                oServletRequest.setAttribute(
                    UserException.USEREVENT_NAME, oEvent);
            }
            List<String> details = new Vector<String>();
            details.add(sCode);
            oServletRequest.setAttribute(
                DetailedUserException.DETAILS_NAME, details);
            
            if (oSession != null)
            {
                String sRequestorID = oSession.getRequestorId();
                if (sRequestorID != null)
                {
                    IRequestor oRequestor = 
                        _requestorPoolFactory.getRequestor(sRequestorID);
                    if (oRequestor != null)
                        oServletRequest.setAttribute(
                            IRequestor.REQUESTOR_ATTRIBUTE_NAME, oRequestor);
                }               
                
                oServletRequest.setAttribute(ISession.LOCALE_NAME, 
                    oSession.getLocale());
                oServletRequest.setAttribute(ISession.ID_NAME, oSession.getId());
            }
           
            oServletRequest.setAttribute(Server.SERVER_ATTRIBUTE_NAME, 
                Engine.getInstance().getServer());
                        
            RequestDispatcher oDispatcher = oServletRequest.getRequestDispatcher(
                _sErrorJspPath); 
            if(oDispatcher != null)
                oDispatcher.forward(oServletRequest, oServletResponse);
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during showing the error page", e);
            throw new ASelectException(ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }
    
    private boolean doLocalErrorHandling(RequestorPool pool)
    {
        if (pool != null)
        {
            String value = (String)pool.getProperty(_sProfileID + PROPERTY_LOCAL_ERROR_HANDLING);
            if (value != null)
            {
                if ("TRUE".equalsIgnoreCase(value))
                    return true;
                else if ("FALSE".equalsIgnoreCase(value))
                    return false;
                else
                {
                    StringBuffer sbDebug = new StringBuffer("Invalid requestorpool property '");
                    sbDebug.append(_sProfileID);
                    sbDebug.append(PROPERTY_LOCAL_ERROR_HANDLING);
                    sbDebug.append("' available for requestorpool with ID '");
                    sbDebug.append(pool.getID());
                    sbDebug.append("': ");
                    _logger.debug(sbDebug.toString());
                }
            }
        }
        
        return _bLocalErrorHandling;
    }
    
    private boolean doRedirectWithPage(IRequestor requestor, RequestorPool requestorPool)
    {
        if (requestor != null)
        {
            String value = (String)requestor.getProperty(_sProfileID + PROPERTY_REDIRECT_PAGE);
            if (value != null)
            {
                if ("TRUE".equalsIgnoreCase(value))
                    return true;
                else if ("FALSE".equalsIgnoreCase(value))
                    return false;
                else
                {
                    StringBuffer sbDebug = new StringBuffer("Invalid requestor property '");
                    sbDebug.append(_sProfileID);
                    sbDebug.append(PROPERTY_REDIRECT_PAGE);
                    sbDebug.append("' available for requestor with ID '");
                    sbDebug.append(requestor.getID());
                    sbDebug.append("': ");
                    _logger.debug(sbDebug.toString());
                }
            }
        }
        
        if (requestorPool != null)
        {
            String value = (String)requestorPool.getProperty(_sProfileID + PROPERTY_REDIRECT_PAGE);
            if (value != null)
            {
                if ("TRUE".equalsIgnoreCase(value))
                    return true;
                else if ("FALSE".equalsIgnoreCase(value))
                    return false;
                else
                {
                    StringBuffer sbDebug = new StringBuffer("Invalid requestorpool property '");
                    sbDebug.append(_sProfileID);
                    sbDebug.append(PROPERTY_REDIRECT_PAGE);
                    sbDebug.append("' available for requestorpool with ID '");
                    sbDebug.append(requestorPool.getID());
                    sbDebug.append("': ");
                    _logger.debug(sbDebug.toString());
                }
            }
        }
        
        return false;
    }
    
    private void forwardToAutoRedirect(HttpServletRequest oServletRequest, 
        HttpServletResponse oServletResponse, String sRedirect, 
        IRequestor oRequestor) throws ASelectException
    {
        try
        {
            oServletRequest.setAttribute("redirect", sRedirect);
            
            if (oRequestor != null)
            {//Add requestor object as attribute
                oServletRequest.setAttribute(IRequestor.REQUESTOR_ATTRIBUTE_NAME, 
                    oRequestor);
            }
            
            oServletRequest.setAttribute(Server.SERVER_ATTRIBUTE_NAME, 
                Engine.getInstance().getServer());
            
            RequestDispatcher oDispatcher = oServletRequest.getRequestDispatcher(
                _sRedirectJspPath); 
            if(oDispatcher != null)
                oDispatcher.forward(oServletRequest, oServletResponse);
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during forward to auto redirect page", e);
            throw new ASelectException(ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }
}