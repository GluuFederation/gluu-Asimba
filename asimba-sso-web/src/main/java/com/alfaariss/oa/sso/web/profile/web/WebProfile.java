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
package com.alfaariss.oa.sso.web.profile.web;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.utility.web.RequestorHelper;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.IService;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.api.sso.ISSOProfile;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.sso.SSOException;
import com.alfaariss.oa.sso.SSOService;
import com.alfaariss.oa.sso.authentication.web.AuthenticationManager;
import com.alfaariss.oa.sso.authorization.web.PostAuthorizationManager;
import com.alfaariss.oa.sso.authorization.web.PreAuthorizationManager;
import com.alfaariss.oa.sso.web.WebSSOServlet;
import com.alfaariss.oa.sso.web.profile.user.UserProfile;
import com.alfaariss.oa.util.logging.SystemLogItem;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.validation.SessionValidator;
import com.alfaariss.oa.util.validation.TGTValidator;
import com.alfaariss.oa.util.web.CookieTool;
import com.alfaariss.oa.util.web.HttpUtils;
import com.alfaariss.oa.util.web.ResponseHeader;

/**
 * Web based Authentication and SSO Component.
 *
 * This Web SSO is part of OA. OA is a professionalized A-Select SSO product 
 * targeting existing and new A-Select customers.
 * <br><br>
 * The WebSSO is the controller servlet which uses JSP pages as view and
 * the {@link SSOService} as business service (model in MVC).
 * 
 * <h4>WebSSO functionality:</h4>
 * 
 * <dl>
 *  <dt>Display TGT</dt>
 *      <dd>Show the users TGT if available (No session required)</dd>
 *  <dt>Pre authorization</dt>
 *      <dd>{@link PreAuthorizationManager}</dd>
 *  <dt>SSO</dt>
 *      <dd>Check for a valid and sufficient SSO session</dd>
 *  <dt>Authentication selection</dt>
 *      <dd>Select a profile to authenticate with</dd>
 *  <dt>Authentication</dt>
 *      <dd>{@link AuthenticationManager}</dd>
 * </dl>
 * <br><br>
 * 
 * The WebSSO should be called by an authentication profile to perform the 
 * actual authentication process.
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class WebProfile implements ISSOProfile, IService, IAuthority
{
    /** Profile ID: user */
    public final static String PROFILE_ID = "web";
    
    /** The name of the authentication profiles */
    public static final String AUTHN_PROFILES_NAME = "authenticationProfiles";
    /** 
     * Attribute name for adding the requestors List&lt;IRequestor&gt; as an 
     * attribute to a <code>Map</code>, request, session, or application.
     */
    public static final String REQUESTORS_ATTRIBUTE_NAME = "requestors";
    /** 
     * Attribute name for adding the authenticaiton profiles 
     * List&lt;IAuthenticationProfile&gt; as an attribute to a <code>Map</code>, 
     * request, session, or application.
     */
    public final static String AUTHN_PROFILES_ATTRIBUTE_NAME = "authnProfiles";
    /** serialVersionUID  */
    private static final long serialVersionUID = 216120079251404994L;
    /** The authority name of the Web SSO.  */
    private static final String AUTHORITY_NAME = "WebSSO";
    
    private static final String DEFAULT_JSP_SELECTION = "/ui/sso/select.jsp"; 
    
    private static final String PROPERTY_WEB_ALWAYS_SHOW_SELECT = ".always_show_select_form";
    
    /** the parameter that triggers changing the locale_language of the session */
    public final static String PARAMETER_LANGUAGE_LOCALE = "locale_language";
    
    protected static final String TGT_ATTR_TGTPROFILE = "TGT-Profile";
    
    private boolean _bStarted;
    
    private String _sSelectionPath;
    private boolean _bShowAlways;
    private SSOService _ssoService;
    private PreAuthorizationManager _preAuthorizationManager;
    private PostAuthorizationManager _postAuthorizationManager;
    private AuthenticationManager _authenticationManager;
    private Log _systemLogger;
    private Log _eventLogger;
    private IConfigurationManager _configurationManager;
    private String _sGlobalPreAuthzProfileID;
    private String _sGlobalPostAuthzProfileID;
    private List<ResponseHeader> _listHeaders;
    private CookieTool _cookieTool;
    
    /**
     * Add profile to context of TGT
     * Both in cookie-context as well as in TGT-attribute
     */
    protected boolean _bTGTProfileEnabled = false;
        
    /**
     * Create a new Web based Authentication and SSO Component.
     * @param authenticationManager The authentication manager.
     */
    public WebProfile(AuthenticationManager authenticationManager)
    {
        _systemLogger = LogFactory.getLog(WebProfile.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
        
        _postAuthorizationManager = new PostAuthorizationManager();
        _preAuthorizationManager = new PreAuthorizationManager();
        _authenticationManager = authenticationManager;
        _ssoService = new SSOService();
        _bStarted = false;
        
        _sSelectionPath = null;
        _cookieTool = null;

        _listHeaders = new Vector<ResponseHeader>();
    }
    
    /**
     * @see com.alfaariss.oa.api.sso.ISSOProfile#getID()
     */
    public String getID()
    {
        return PROFILE_ID;
    }

    /**
     * @see com.alfaariss.oa.api.sso.ISSOProfile#init(javax.servlet.ServletContext, com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element, org.w3c.dom.Element)
     */
    public void init(ServletContext context,
        IConfigurationManager configurationManager, Element eParent, 
        Element eSpecific) throws OAException
    {
        if(configurationManager == null)
            throw new IllegalArgumentException(
                "Supplied ConfigurationManager is empty");
               
        _configurationManager = configurationManager;
        
        Engine oEngine = Engine.getInstance();
        Server oServer = oEngine.getServer();
        if (oServer == null)
        {
            _systemLogger.error("Server object could not be retrieved");
            throw new OAException(SystemErrors.ERROR_INIT);
        }
        _sGlobalPreAuthzProfileID = oServer.getPreAuthorizationProfileID();
        _sGlobalPostAuthzProfileID = oServer.getPostAuthorizationProfileID();
        
        //Start SSO service
        _ssoService.start(configurationManager, eParent);
        
        //SSO + SelectionPath
        readDefaultConfiguration(eParent); 
        
        _cookieTool = new CookieTool(configurationManager, eParent);
        
        //Response headers configuration
        readHeadersConfiguration(eParent);
        
        //Pre authorization configuration
        Element ePreAuthorization = _configurationManager.getSection(
            eParent, "preauthorization");
        if(ePreAuthorization == null)
        {
            _systemLogger.info(
                "No preauthorization configuration found, pre authorization is disabled");
        }
        else
        {
            _preAuthorizationManager.start(_configurationManager, ePreAuthorization);
        }
        
        //Post authorization configuration
        Element ePostAuthorization = _configurationManager.getSection(
            eParent, "postauthorization");
        if(ePostAuthorization == null)
        {
            _systemLogger.info(
                "No postauthorization configuration found, post authorization is disabled");
        }
        else
        {
            _postAuthorizationManager.start(_configurationManager, ePostAuthorization);
        }
        
        //Authentication configuration
        Element eAuthentication = _configurationManager.getSection(
            eParent, "authentication");
        if(eAuthentication == null)
        {
            _systemLogger.error("No authentication configuration found");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        readShowAlwaysConfiguration(eAuthentication);
        
        /* figure out configuration for adding profile to TGT context */
        Element elTGT = _configurationManager.getSection(eParent, "tgt");
        if (elTGT != null) {
        	_bTGTProfileEnabled = establishOptionalBooleanAttribute(
        			elTGT, "addprofile", "websso/tgt");
        }
        
        _systemLogger.info("WebSSO started [Localization; TGTProfile patches]");
        _bStarted = true;
    }

    /**
     * @see IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME;
    }

    /**
     * Process the WebSSO HTTP requests.
     * <br><br>
     * All requests require a session: 
     * <ol>
     *  <li>Request attribute ({@link ISession#ID_NAME}=<code>session</code>)</li>
     *   <li>Request parameter ({@link ISession#ID_NAME}=<code>session id</code>)</li>
     * </ol> 
     * 
     * <h4>The following session states are processed:</h4>
     * <dl>
     *  <dt>{@link SessionState#SESSION_CREATED}, {@link SessionState#PRE_AUTHZ_IN_PROGRESS}</dt>
     *  <dd>Perform pre authorization</dd>
     *  <dt>{@link SessionState#PRE_AUTHZ_OK}</dt>
     *  <dd>Check SSO TGT</dd>
     *  <dt>{@link SessionState#AUTHN_SELECTION_IN_PROGRESS}</dt>
     *  <dd>Perform authenctication profile selection</dd>
     *  <dt>{@link SessionState#AUTHN_SELECTION_OK}, {@link SessionState#AUTHN_IN_PROGRESS}</dt>
     *  <dd>Perform authenctication profile selection</dd>
     *  <dt><code>default</code></dt>
     *  <dd>All other states are redirected back to the profile used</dd>
     * </dl>
     * 
     * @see com.alfaariss.oa.api.IService#service(
     *  javax.servlet.http.HttpServletRequest, 
     *  javax.servlet.http.HttpServletResponse)
     */
    public void service(HttpServletRequest oRequest, 
        HttpServletResponse oResponse) throws OAException
    {    
        ISession oSession = null;
        try
        {
            if(!_bStarted) //Check sso state
            {
                oResponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                return;
            }
            
            //Disable caching
            HttpUtils.setDisableCachingHttpHeaders(oRequest, oResponse);     

            //retrieve session attribute (trusted)
            oSession = (ISession)oRequest.getAttribute(
                ISession.ID_NAME); 
                                      
            if(oSession == null) //No session found yet
            {
                //Retrieve session id (not trusted)
                String sId = oRequest.getParameter(ISession.ID_NAME);
                if(sId != null)
                {
                    //TODO session id as cookie? (Erwin)
                    if(!SessionValidator.validateDefaultSessionId(sId))
                    {
                        _systemLogger.warn("Invalid session id in request: " + sId);
                        throw new UserException(UserEvent.REQUEST_INVALID);
                    }                
                    oSession = _ssoService.getSession(sId);                    
                }
                if(oSession == null) //No session found
                {
                    //Show default page
                    _systemLogger.debug("No valid session found");
                    handleStartPage(oRequest, oResponse);
                }               
            }    
            
            if(oSession != null) //Session found
            {
                //Check session expiration
                if(oSession.isExpired())
                {                               
                    throw new UserException(UserEvent.SESSION_EXPIRED);
                }
                
                //Check cancelled
                if(oRequest.getParameter("cancel") != null)
                {
                    try
                    {
                        oSession.setState(SessionState.USER_CANCELLED);
                        oSession.persist();                     
                        _eventLogger.info(new UserEventLogItem(
                            oSession, oRequest.getRemoteAddr(), 
                            UserEvent.USER_CANCELLED, this, null));
                    }
                    catch(OAException e)
                    {
                        _systemLogger.warn("Could not store session");
                        //Wrap exception
                        throw new SSOException(e.getCode(), e);
                    }
                }
                
                /* dopey adds: change locate from request */
                if (oRequest.getParameter(PARAMETER_LANGUAGE_LOCALE) != null)
                {
                	String sNewLocale = oRequest.getParameter(PARAMETER_LANGUAGE_LOCALE);
                	if (! sNewLocale.equals("")) {
	                	oSession.setLocale(new Locale(sNewLocale));
	                	oSession.persist();
	                	_systemLogger.info("User changed session 'locale_language' to " +
	                			sNewLocale);
                	}
                }
                /* end-of-locale-updates */
                
                RequestorPool oRequestorPool = _ssoService.getRequestorPool(oSession);                   
                if(oRequestorPool == null)
                {
                    _systemLogger.warn(new SystemLogItem(oSession.getId(), 
                        SystemErrors.ERROR_INTERNAL, 
                        "Could not retrieve requestor pool from session"));
                    throw new SSOException(SystemErrors.ERROR_INTERNAL);
                }

                //switch state
                switch(oSession.getState())
                {
                    case SESSION_CREATED:
                    {
                        List<IAuthenticationProfile> listAuthNProfiles = 
                            _ssoService.getAllAuthNProfiles(oRequestorPool);
                        if (listAuthNProfiles.isEmpty())
                        {
                            //DD A requestor pool must be configured with one or more authN profiles 
                            _systemLogger.warn("Not one enabled authentication profile for requestor pool: " 
                                + oRequestorPool.getID());
                            throw new SSOException(SystemErrors.ERROR_INTERNAL);  
                        }
                        
                        oSession.setAuthNProfiles(listAuthNProfiles);
                        oSession.setState(SessionState.PRE_AUTHZ_IN_PROGRESS);
                        
                        if (oRequestorPool.isForcedAuthenticate())
                        {
                            oSession.setForcedAuthentication(true);
                            _systemLogger.debug("Forced by requestor pool: Force authentication");
                        }
                        
                        handlePreAuthorization(oRequest, oResponse, oSession, oRequestorPool);  
                        break;
                    }
                    case PRE_AUTHZ_IN_PROGRESS:   
                    {   
                        handlePreAuthorization(oRequest, oResponse, oSession, oRequestorPool);  
                        break;
                    }
                    case PRE_AUTHZ_OK:   
                    {
                        checkTGT(oRequest, oResponse, oSession, oRequestorPool);  
                        break;
                    }
                    case AUTHN_SELECTION_IN_PROGRESS:
                    {
                        handleAuthenticationSelection(oRequest, oResponse, 
                            oSession, oRequestorPool);
                        break;
                    }
                    case AUTHN_SELECTION_OK:
                    case AUTHN_IN_PROGRESS:
                    {
                        handleAuthentication(oRequest, oResponse, oSession, 
                            oRequestorPool, oSession.getSelectedAuthNProfile());
                        break;
                    }
                    case POST_AUTHZ_IN_PROGRESS:
                    {
                        //handle post authz
                        handlePostAuthorization(oRequest, oResponse, oSession, oRequestorPool);  
                        break;
                    }
                    case POST_AUTHZ_OK:
                    case POST_AUTHZ_FAILED:
                    case PRE_AUTHZ_FAILED:
                    case AUTHN_SELECTION_FAILED:                    
                    case AUTHN_OK:
                    case USER_CANCELLED:
                    case AUTHN_FAILED:
                    case AUTHN_NOT_SUPPORTED:              
                    case USER_BLOCKED:
                    case USER_UNKNOWN:                
                    default: //Redirect to profile
                    {
                        _systemLogger.debug(new SystemLogItem(
                            oSession.getId(), SystemErrors.OK, 
                            "Redirect back to Profile" ));                                     
                        oResponse.sendRedirect(oSession.getProfileURL());
                        break;
                    }                                                     
                }           
            }
        }
        catch(UserException e) //User error
        {            
            if(oSession != null)
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(),e.getEvent(),this,null));    
            else
                _eventLogger.info(new UserEventLogItem(null,null,null, 
                    e.getEvent(),null,oRequest.getRemoteAddr(),null,this,null));   
            
            if(!oResponse.isCommitted()) 
            {
                try
                {
                    oResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
                }
                catch (IOException e1)
                {
                    _systemLogger.warn("Could not send response",e1);
                }             
            }  
        }   
        catch(SSOException e) //Internal error in websso
        {
            //Log to event logging
            if(oSession != null)
            {
                _eventLogger.info(new UserEventLogItem(
                    oSession, oRequest.getRemoteAddr(), 
                    UserEvent.INTERNAL_ERROR, this, null));              
            }
            else
            {
                _eventLogger.info(new UserEventLogItem(null, null, null, 
                    UserEvent.INTERNAL_ERROR,  null, 
                    oRequest.getRemoteAddr(), null, this, null));
            }
            handleError(oRequest, oResponse, oSession, e, e.getCode());  
        }         
        catch(OAException e) //Internal error in methods
        {
            handleError(oRequest, oResponse, oSession, e, e.getCode());  
        }        
        catch(Exception e)  //Internal error 
        {
            handleError(oRequest, oResponse, oSession, e, 
                SystemErrors.ERROR_INTERNAL);  
        }       
    }

    /**
     * Destroys the Servlet.
     * @see javax.servlet.Servlet#destroy()
     */
    public void destroy()
    {
        _bStarted = false;
        _cookieTool = null;
        
        if(_ssoService != null)
            _ssoService.stop();
        
        if(_preAuthorizationManager != null)
            _preAuthorizationManager.stop();
        if(_postAuthorizationManager != null)
            _postAuthorizationManager.stop();
        
        _systemLogger.info("WebSSO stopped");   
    }

    
    //handles exceptions of service() method
    private void handleError(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession, 
        Throwable t, int iErrorCode)
    {
        if(oSession != null)
        {
            _systemLogger.error(new SystemLogItem(oSession.getId(), 
                iErrorCode, "Internal error while processing request"), t);  
            
            try
            {
                //Set request attributes if available
                oRequest.setAttribute(ISession.LOCALE_NAME, 
                    oSession.getLocale());
                
                oRequest.setAttribute(Server.SERVER_ATTRIBUTE_NAME, 
                    Engine.getInstance().getServer());
                
                
                String sRequestorID = oSession.getRequestorId();
                if (sRequestorID != null)
                {
                    IRequestor oRequestor = 
                        _ssoService.getRequestor(oSession);
                    if (oRequestor != null)
                        oRequest.setAttribute(
                            IRequestor.REQUESTOR_ATTRIBUTE_NAME, oRequestor);
                }
            }
            catch(Exception e)
            {
                _systemLogger.error("could not set request attributes", e);
            }
            
            oSession.expire();
            try
            {
                oSession.persist();
            }
            catch (PersistenceException e1)
            {
                _systemLogger.error("Could not persist session", e1);
            }
        }
        else
        {          
            _systemLogger.error(
                "Internal error while processing request", t);
        }
        
        if(!oResponse.isCommitted()) 
        {
            try
            {
                oResponse.sendError(
                      HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
            catch (IOException e1)
            {
                _systemLogger.warn("Could not send response", e1);
            }            
        }
    }
    
    //Read standard configuration    
    private void readDefaultConfiguration(Element eConfig) throws OAException
    {
        assert eConfig != null : "Supplied config == null";
        //SSO       
        _sSelectionPath = DEFAULT_JSP_SELECTION;
        
        Element eView =  _configurationManager.getSection(eConfig, "view");
        if(eView == null)
        {
            _systemLogger.warn("No optional 'view' section configuration found, using default");
        }
        else
        {
            Element ePage = _configurationManager.getSection(
                eView, "profile_selection");
            if (ePage == null)
            {
                _systemLogger.warn("No optional 'profile_selection' section found in 'view' section in configuration, using default");
            }
            else
            {
                _sSelectionPath = _configurationManager.getParam(
                    ePage, "path");
                if(_sSelectionPath == null || _sSelectionPath.length() == 0)
                {
                    _systemLogger.error("No 'path' parameter in 'profile_selection' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
        }
        
        _systemLogger.warn("Using profile selection JSP: " + _sSelectionPath);
    }
        
    //Read ShowAllways configuration
    private void readShowAlwaysConfiguration(
        Element eAuthentication) throws OAException
    {
        assert eAuthentication != null 
            : "Supplied authentication config element == null";
        
        _bShowAlways = false;
        String sShowAllways = _configurationManager.getParam(eAuthentication, 
            "always_show_select_form");
        if (sShowAllways != null)
        {
            if("true".equalsIgnoreCase(sShowAllways))
                _bShowAlways = true;
            else if (!"false".equalsIgnoreCase(sShowAllways))
            {
                _systemLogger.error("Invalid value for 'always_show_select_form' item found in configuration: " 
                    + sShowAllways);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            _systemLogger.info("Optional 'always_show_select_form' item is configured with value: " 
                + _bShowAlways);
        }
    }
    
    /**
     * Helper to establish the boolean value of a child of an element
     * @param elElement Element to look into
     * @param sAttributeName Name of the child element to find value for
     * @param sParentElementName Name of the parent element (for logging purposes)
     * @return true or false
     * @throws OAException when invalid value was configured
     */
    private boolean establishOptionalBooleanAttribute(Element elElement, 
    		String sAttributeName, String sParentElementName)
    throws OAException
    {
    	boolean b = false;
    	String s = _configurationManager.getParam(elElement, sAttributeName);
    	if (s != null) {
    		if ("true".equalsIgnoreCase(s)) {
    			b = true;
    		} else if (!"false".equalsIgnoreCase(s)) {
    			_systemLogger.error("Invalid value for optional @"+sAttributeName+"-attribute of "+
    					sParentElementName+": "+s);
    			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
    		}
    		_systemLogger.info("Optional '"+sAttributeName+"' item is configured with value: " 
                    + b);
    	}
    	
    	return b;
    }
    
    /**
     * Reads response headers configuration.
     *
     * @param eConfig
     * @throws OAException
     * @since 1.1
     */
    private void readHeadersConfiguration(Element eConfig) throws OAException
    {
        assert eConfig != null : "Supplied config == null";
        
        //the list is already created in the constructor, for restart purposes it must be cleared.
        _listHeaders.clear();
        
        Element eHeaders = _configurationManager.getSection(eConfig, "headers");
        if (eHeaders != null)
        {
            Element eHeader = _configurationManager.getSection(eHeaders, "header");
            while (eHeader != null)
            {
                //DD Servlet response headers don't have to be unique, multiple headers with the same name are multivalue headers.
                
                ResponseHeader header = new ResponseHeader(_configurationManager, eHeader);
                _listHeaders.add(header);
                
                _systemLogger.info("Adding header: " + header.toString());
                
                eHeader = _configurationManager.getNextSection(eHeader);
            }
        }
    }
    
    //Show the default WebSSO page
    private void handleStartPage(HttpServletRequest oRequest, 
        HttpServletResponse oResponse) 
        throws SSOException, IOException, ServletException
    {   
        try
        {
            String sServletPath = oRequest.getServletPath();
            StringBuffer sbServletPath = new StringBuffer(sServletPath);
            if (!sServletPath.endsWith("/"))
                sbServletPath.append("/");
            sbServletPath.append(UserProfile.PROFILE_ID);
            
            RequestDispatcher oDispatcher = 
                oRequest.getRequestDispatcher(sbServletPath.toString()); 
            if(oDispatcher != null)
                oDispatcher.forward(oRequest, oResponse);
            else
            {
                _systemLogger.fatal("Forward request not supported: " + sbServletPath.toString());
                throw new SSOException(SystemErrors.ERROR_INTERNAL);
            }
        }
        catch(SSOException e)
        {
            throw e;
        }
    }
    
    //Pre authorize
    private void handlePreAuthorization(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession, 
        RequestorPool oRequestorPool) throws OAException, IOException, UserException
    {      
        if(_preAuthorizationManager.isEnabled()) //Pre-authorization enabled
        {
            //Perform pre-authorization    
            _preAuthorizationManager.authorize(oRequest, oResponse, oSession, 
                oRequestorPool);
            try
            {
                switch(oSession.getState())
                {               
                    case PRE_AUTHZ_FAILED:
                    {                    
                        try
                        {
                            //Persist Session             
                            oSession.persist();
                        }
                        catch(OAException e)
                        {
                            _systemLogger.warn("Could not persist session",e);
                            //Wrap exception
                            throw new SSOException(e.getCode(), e);
                        }
                        
                        //Redirect to profile
                        oResponse.sendRedirect(oSession.getProfileURL());
                        break;
                    }
                    case PRE_AUTHZ_OK:
                    {
                        StringBuffer sbMessage = new StringBuffer();
                        if (_sGlobalPreAuthzProfileID != null)
                            sbMessage.append(_sGlobalPreAuthzProfileID);
                        
                        String sPoolPreAuthProfileID = oRequestorPool.getPreAuthorizationProfileID();
                        if (sPoolPreAuthProfileID != null)
                        {
                            if (_sGlobalPreAuthzProfileID != null)
                                sbMessage.append(",");
                            
                            sbMessage.append(sPoolPreAuthProfileID);
                        }
                        
                        _eventLogger.info(new UserEventLogItem(
                            oSession,oRequest.getRemoteAddr(), UserEvent.USER_PRE_AUTHORIZED, 
                            this, sbMessage.toString())); 
                        
                        //Continue with checking for a TGT 
                        checkTGT(oRequest, oResponse, oSession, oRequestorPool);
                        break;
                    }
                    case PRE_AUTHZ_IN_PROGRESS:
                    {
                        //AuthR Manager handles request                
                        break;
                    }
                    case USER_CANCELLED:
                    {
                        //Canceled  
                        try
                        {
                            //Persist Session             
                            oSession.persist();
                        }
                        catch(OAException e)
                        {
                            _systemLogger.warn("Could not persist session",e);
                            //Wrap exception
                            throw new SSOException(e.getCode(), e);
                        }
                        
                        //Authentication log performed by manager  
                        //Redirect to profile
                        oResponse.sendRedirect(oSession.getProfileURL());
                        break;
                    }
                    default:
                    {
                        //Invalid state
                        _systemLogger.error(new SystemLogItem(oSession.getId(), 
                            SystemErrors.ERROR_INTERNAL,
                            "Session state not supported during preautorization"));
                        throw new SSOException(SystemErrors.ERROR_INTERNAL);
                    }
                } 
            }
            catch(OAException e)
            {
                throw e;
            }           
        }
        else
        {
            oSession.setState(SessionState.PRE_AUTHZ_OK);
            _eventLogger.info(
                new UserEventLogItem(oSession, oRequest.getRemoteAddr(), 
                    UserEvent.USER_PRE_AUTHORIZED, this, null));
            //Continue with checking for a TGT 
            checkTGT(oRequest, oResponse, oSession, oRequestorPool);
        }        
       
    }
    
    //Post authorize
    private void handlePostAuthorization(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession, 
        RequestorPool oRequestorPool) throws OAException, IOException
    {      
        if(_postAuthorizationManager.isEnabled()) //Post-authorization enabled
        {
            //Perform post-authorization    
            _postAuthorizationManager.authorize(oRequest, oResponse, oSession, 
                oRequestorPool);
            try
            {
                switch(oSession.getState())
                {               
                    case POST_AUTHZ_FAILED:
                    {                    
                        try
                        {
                            //Persist Session             
                            oSession.persist();
                        }
                        catch(OAException e)
                        {
                            _systemLogger.warn("Could not persist session",e);
                            //Wrap exception
                            throw new SSOException(e.getCode(), e);
                        }
                        
                        //Redirect to profile
                        oResponse.sendRedirect(oSession.getProfileURL());
                        break;
                    }
                    case POST_AUTHZ_OK:
                    {
                        StringBuffer sbMessage = new StringBuffer();
                        if (_sGlobalPostAuthzProfileID != null)
                            sbMessage.append(_sGlobalPostAuthzProfileID);
                        
                        String sPoolPostAuthProfileID = oRequestorPool.getPostAuthorizationProfileID();
                        if (sPoolPostAuthProfileID != null)
                        {
                            if (_sGlobalPostAuthzProfileID != null)
                                sbMessage.append(",");
                            
                            sbMessage.append(sPoolPostAuthProfileID);
                        }
                        
                        _eventLogger.info(new UserEventLogItem(
                            oSession,oRequest.getRemoteAddr(), UserEvent.USER_POST_AUTHORIZED, 
                            this, sbMessage.toString())); 
                        
                        finishAuthentication(oResponse, oSession, oRequestorPool);
                        
                        break;
                    }
                    case POST_AUTHZ_IN_PROGRESS:
                    {
                        //AuthZ Manager handles request                
                        break;
                    }
                    case USER_CANCELLED:
                    {
                        //Canceled  
                        try
                        {
                            //Persist Session             
                            oSession.persist();
                        }
                        catch(OAException e)
                        {
                            _systemLogger.warn("Could not persist session",e);
                            //Wrap exception
                            throw new SSOException(e.getCode(), e);
                        }
                        
                        //Authentication log performed by manager  
                        //Redirect to profile
                        oResponse.sendRedirect(oSession.getProfileURL());
                        break;
                    }
                    default:
                    {
                        //Invalid state
                        _systemLogger.error(new SystemLogItem(oSession.getId(), 
                            SystemErrors.ERROR_INTERNAL,
                            "Session state not supported during postautorization"));
                        throw new SSOException(SystemErrors.ERROR_INTERNAL);
                    }
                } 
            }
            catch(OAException e)
            {
                throw e;
            }           
        }
        else
        {
            _eventLogger.info(
                new UserEventLogItem(oSession, oRequest.getRemoteAddr(), 
                    UserEvent.USER_POST_AUTHORIZED, this, null));
            
            finishAuthentication(oResponse, oSession, oRequestorPool);
        }        
       
    }
    
    //Check for tgt that might be present
    private void checkTGT(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession, 
        RequestorPool oRequestorPool) 
        throws SSOException, IOException, UserException
    {      
        try
        {
            boolean bTGTSufficient = false;
            try
            {
                //Get decoded TGT from cookie value
                String sTGTId = _cookieTool.getCookieValue(
                    WebSSOServlet.TGT_COOKIE_NAME, oRequest);
                
                if(sTGTId != null)
                {
                    //Verify cookie value
                    if(!TGTValidator.validateDefaultTGTId(sTGTId))
                    {         
                        _systemLogger.debug("Invalid request, tgt id invalid: " + sTGTId);                
                        throw new UserException(UserEvent.REQUEST_INVALID);
                    }            
                }
                
                /* CloudIAM: When enabled: check TGT-profile to TGT-attributes */
                boolean bAllowedTGTProfile = true;
                if (_bTGTProfileEnabled && sTGTId != null) {
                    String sProfileURL = RequestorHelper.entityHostFromRequestor(
                    		oSession.getProfileURL());
                    
                    _systemLogger.debug("Checking whether a TGT is valid for profile " + sProfileURL);
                    
                    /* no TGT, then the TGTProfile is allowed */
                    ITGT oTGT = _ssoService.getTGT(sTGTId);
                    if (oTGT != null) {
                    	String sTGTProfile = (String) oTGT.getAttributes().get(
                    			WebProfile.class, TGT_ATTR_TGTPROFILE);
                    	
                    	if (sTGTProfile == null) {
                    		/* No TGTProfile in TGT? */
                    		_systemLogger.debug("No TGT Profile with TGT: " + sTGTId);                
                            throw new UserException(UserEvent.REQUEST_INVALID);
                    	}
                    	
                    	if (! sTGTProfile.equalsIgnoreCase(sProfileURL)) {
                    		_systemLogger.debug("TGT was issued for profile "+sTGTProfile+
                    				"; but request is for profile "+sProfileURL+". TGT is ignored for this request.");
                    		bAllowedTGTProfile = false;
                    	}
                    }
                }
                
                /* inspect whether TGT is authorizing access whenever 
                 * either TGTProfile is ignored
                 * or TGTProfile is enabled and the TGTProfile value matches the request */
                if ((!_bTGTProfileEnabled) || 
                	(_bTGTProfileEnabled && bAllowedTGTProfile)) {
	                bTGTSufficient = _ssoService.checkSingleSignon(
	                    oSession, sTGTId, oRequestorPool);
                }
                /* CloudIAM; incorporated checkSingleSignon in TGTProfile flow */
            }       
            catch(UserException e) //Invalid TGT
            {
                //authentication log Invalid TGT user
                _eventLogger.info(new UserEventLogItem(
                    oSession,oRequest.getRemoteAddr(), 
                    e.getEvent(), this, null));
                
                _cookieTool.removeCookie(WebSSOServlet.TGT_COOKIE_NAME, 
                    oRequest, oResponse);
            }
    
            if(bTGTSufficient) //TGT sufficiant
            {   
                _eventLogger.info(new UserEventLogItem(
                    oSession,oRequest.getRemoteAddr(), 
                    UserEvent.USER_AUTHENTICATED, this, "TGT"));   

                oSession.setState(SessionState.POST_AUTHZ_IN_PROGRESS);
                
                _ssoService.gatherAttributes(oSession);
                
                handlePostAuthorization(oRequest, oResponse, oSession, oRequestorPool);
            }
            else if (oSession.isPassive())
            {
                //DD if passive is enabled then an error must be returned directly
                
                oSession.setState(SessionState.PASSIVE_FAILED);
                try
                {
                    //Persist Session             
                    oSession.persist();
                }
                catch(OAException e)
                {
                    _systemLogger.warn("Could not persist session",e);
                    //Wrap exception
                    throw new SSOException(e.getCode(), e);
                }
                
                //Redirect to profile
                oResponse.sendRedirect(oSession.getProfileURL());
            }
            else //Proceed with authentication
            {        
                oSession.setState(SessionState.AUTHN_SELECTION_IN_PROGRESS);
                                
                _eventLogger.info(new UserEventLogItem(
                    oSession,oRequest.getRemoteAddr(), 
                    UserEvent.TGT_NOT_SUFFICIENT, this, null));
                //Authentication selection
                handleAuthenticationSelection(oRequest, oResponse, oSession, 
                    oRequestorPool);
            }
        }
        catch(SSOException e)
        {
            throw e;
        }
        catch(OAException e)
        {
            _systemLogger.warn("Could not check TGT",e);
            //Wrap exception
            throw new SSOException(e.getCode(), e);
        }
    }  
    
    //Select authentication
    private void handleAuthenticationSelection(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession, 
        RequestorPool oRequestorPool) throws SSOException, UserException
    {    
        try
        {   
            IRequestor requestor = 
                _ssoService.getRequestor(oSession.getRequestorId());
            
            IAuthenticationProfile oSelectedProfile = 
                _ssoService.getSelectedAuthNProfile(oSession, 
                    oRequest.getParameter("profile"), 
                    doShowAlways(oRequestorPool, requestor));
            
            if (oSelectedProfile != null)
            {
                if(oSession.getState() == SessionState.AUTHN_NOT_SUPPORTED)
                {
                    oRequest.setAttribute(UserException.USEREVENT_NAME, 
                        UserEvent.AUTHN_METHOD_NOT_SUPPORTED);  
                } 
                
                oSession.setState(SessionState.AUTHN_SELECTION_OK);
                
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.AUTHN_PROFILE_SELECTED, this, null)); 
                
                handleAuthentication(oRequest, oResponse, oSession, oRequestorPool, oSelectedProfile);
            }
            else
            {
                if(oSession.getAuthNProfiles().isEmpty())  
                {
                    oSession.setState(SessionState.AUTHN_SELECTION_FAILED);
                    _systemLogger.error("No allowed authentication profiles available for session: " 
                        + oSession.getId());
                    
                    try
                    {
                        oSession.persist();
                    }
                    catch(OAException e)
                    {
                        _systemLogger.warn("Could not persists session",e);
                        //Wrap exception
                        throw new SSOException(e.getCode(), e);
                    }
                    //Authentication log 
                    _eventLogger.info(new UserEventLogItem(oSession, 
                        oRequest.getRemoteAddr(), 
                        UserEvent.AUTHN_PROFILE_NOT_AVAILABLE, this,
                        oRequestorPool.getID())); 
                    //Redirect to profile
                    oResponse.sendRedirect(oSession.getProfileURL());
                }   
                else
                {                    
                    showSelectPage(oRequest, oResponse, oSession);
                }
            }
        }
        catch(UserException e) //Selection failed
        {            
            throw e;          
        }
        catch(SSOException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.error("Internal error during authN profile selection", e);
            throw new SSOException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    //Show selection page
    private void showSelectPage(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession) 
        throws SSOException
    {
        try
        {
            //Set optional warning
            if(oSession.getState() == SessionState.AUTHN_NOT_SUPPORTED)
            {
                oRequest.setAttribute(UserException.USEREVENT_NAME, 
                    UserEvent.AUTHN_METHOD_NOT_SUPPORTED);  
            }   
            
            //Save session
            oSession.setState(SessionState.AUTHN_SELECTION_IN_PROGRESS);
            oSession.persist();
           
            //Add requestor object as attribute
            oRequest.setAttribute(IRequestor.REQUESTOR_ATTRIBUTE_NAME, 
                _ssoService.getRequestor(oSession));
                
            //Set authenticationProfiles map as attribute
            oRequest.setAttribute(AUTHN_PROFILES_NAME, oSession.getAuthNProfiles());  
            //Set session ID and locale as attribute              
            oRequest.setAttribute(ISession.ID_NAME, oSession.getId());
            oRequest.setAttribute(ISession.LOCALE_NAME, oSession.getLocale());
            //Set server info as attribute
            oRequest.setAttribute(Server.SERVER_ATTRIBUTE_NAME, 
                Engine.getInstance().getServer());
            //Forward to page                
            RequestDispatcher oDispatcher = oRequest.getRequestDispatcher(_sSelectionPath); 
            if(oDispatcher == null)
            {
                _systemLogger.fatal(new SystemLogItem(oSession.getId(),
                    SystemErrors.ERROR_INTERNAL, "Forward request not supported"));
                throw new SSOException(SystemErrors.ERROR_INTERNAL);
            }
           
            //Redirect user
            oDispatcher.forward(oRequest, oResponse);
        }
        catch (SSOException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            //Wrap exception
            throw new SSOException(e.getCode(), e);
        }
        catch (Exception e)
        {
            _systemLogger.fatal("Could not forward request with session: " 
                + oSession.getId(), e);
            throw new SSOException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    //Perform authentication
    private void handleAuthentication(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession, 
        RequestorPool oRequestorPool, 
        IAuthenticationProfile oSelectedAuthNProfile) 
        throws OAException, IOException, UserException
    {   
        _authenticationManager.authenticate(
            oSelectedAuthNProfile, oRequest, oResponse, oSession);
        
        switch(oSession.getState())
        {
            case AUTHN_OK:
            {  
                oSession.setState(SessionState.POST_AUTHZ_IN_PROGRESS);
                
                if(oSession.getUser() == null)
                {
                    //Invalid state
                    _systemLogger.error(new SystemLogItem(oSession.getId(), 
                        SystemErrors.ERROR_INTERNAL,
                        "No user added during authentication, invalid configuration"));
                    throw new SSOException(SystemErrors.ERROR_INTERNAL);
                }
                
                ITGT oTGT = _ssoService.handleSingleSignon(oSession);
                if(oTGT != null) 
                {
                    /* CloudIAM: Add TGT-profile to TGT-attributes */
                    String sProfileID = RequestorHelper.entityHostFromRequestor(
                    		oSession.getProfileURL()); 
                    
                    //set TGT cookie                 
                    Cookie cTGT;
                    if (_bTGTProfileEnabled) {
                    	/* Create cookie in .../profiles/[profile] context */
	                    cTGT =  _cookieTool.createCookie(
	                    		WebSSOServlet.TGT_COOKIE_NAME, oTGT.getId(), "profiles/"+sProfileID, oRequest);
	                    
	                    /* add profile context as TGT-attribute */
	                    oTGT.getAttributes().put(WebProfile.class, TGT_ATTR_TGTPROFILE, sProfileID);
	                    oTGT.persist();
                    } else {
                    	cTGT = _cookieTool.createCookie(
                    			WebSSOServlet.TGT_COOKIE_NAME, oTGT.getId(), oRequest);
                    }
                    
                    /* End of CloudIAM TGT-profile */
                    
                    oResponse.addCookie(cTGT);
                    addHeaders(oResponse);
                }
                
                try
                {
                    //Persist Session             
                    oSession.persist();
                }
                catch(OAException e)
                {
                    _systemLogger.warn("Could not persist session",e);
                    //Wrap exception
                    throw new SSOException(e.getCode(), e);
                }
                //Authentication log -> user authenticated + sProfileId  
                _eventLogger.info(new UserEventLogItem(
                    oSession,oRequest.getRemoteAddr(), UserEvent.USER_AUTHENTICATED, 
                    this, oSelectedAuthNProfile.getID())); 
                
                _ssoService.gatherAttributes(oSession);
                
                //handle post authz
                handlePostAuthorization(oRequest, oResponse, oSession, oRequestorPool); 
                break;
            }
            case AUTHN_NOT_SUPPORTED:
            {
                //Fallback to AuthN selection       
                //set the authN profile list with the not supported profile filtered out
                List<IAuthenticationProfile> listProfiles = oSession.getAuthNProfiles();
                listProfiles.remove(oSelectedAuthNProfile);
                oSession.setAuthNProfiles(listProfiles);
                
                handleAuthenticationSelection(
                    oRequest, oResponse, oSession, oRequestorPool);
                break;
            }
            case AUTHN_FAILED:            
            case USER_CANCELLED:
            case USER_BLOCKED:
            case USER_UNKNOWN:
            {
                //Authentication finished
                try
                {
                    //Persist Session 
                    oSession.persist();  
                }
                catch(OAException e)
                {
                    _systemLogger.warn("Could not persist session",e);
                    //Wrap exception
                    throw new SSOException(e.getCode(), e);
                }
                //Authentication log performed by manager  
                //Redirect to profile
                oResponse.sendRedirect(oSession.getProfileURL());
                break;
            }
            case AUTHN_IN_PROGRESS:
            {
                //AuthN Manager handles request                
                break;
            }
            default:
            {
                //Invalid state
                _systemLogger.fatal(new SystemLogItem(oSession.getId(), 
                    SystemErrors.ERROR_INTERNAL,
                    "Session state not supported during authentication"));
                throw new SSOException(SystemErrors.ERROR_INTERNAL);
            }
        } 
    }    
   
    /**
     * Adds optional configured headers to the response. 
     * @param response The response where the headers should be added to.
     * @since 1.1
     */
    private void addHeaders(HttpServletResponse response)
    {
        for (int i = 0; i < _listHeaders.size(); i++)
        {
            ResponseHeader header = _listHeaders.get(i);
            response.addHeader(header.getName(), header.getValue());
        }
    }
    
    private void finishAuthentication(HttpServletResponse response, 
        ISession session, RequestorPool pool) throws OAException, IOException
    {
        //apply ARP
        _ssoService.performAttributeReleasePolicy(session, 
            pool.getAttributeReleasePolicyID());
        
        //Redirect to profile
        session.setState(SessionState.AUTHN_OK);
        session.persist();

        response.sendRedirect(session.getProfileURL());
    }

    private boolean doShowAlways(RequestorPool pool, IRequestor requestor) 
    {
        String propertyName = PROFILE_ID + PROPERTY_WEB_ALWAYS_SHOW_SELECT;
        
        String value = (String)requestor.getProperty(propertyName);
        if (value != null)
        {
            if ("TRUE".equalsIgnoreCase(value))
                return true;
            else if ("FALSE".equalsIgnoreCase(value))
                return false;
            else
            {
                StringBuffer sbDebug = new StringBuffer("Invalid requestor specific '");
                sbDebug.append(propertyName);
                sbDebug.append("' property found for requestor with ID '");
                sbDebug.append(requestor.getID());
                sbDebug.append("': ");
                sbDebug.append(value);
                _systemLogger.error(sbDebug.toString());
            }
        }
        else
        {
            StringBuffer sbDebug = new StringBuffer("No (optional) requestor specific '");
            sbDebug.append(propertyName);
            sbDebug.append("' property found for requestor with ID: ");
            sbDebug.append(requestor.getID());
            _systemLogger.debug(sbDebug.toString());
        }
        
        value = (String)pool.getProperty(propertyName);
        if (value != null)
        {
            if ("TRUE".equalsIgnoreCase(value))
                return true;
            else if ("FALSE".equalsIgnoreCase(value))
                return false;
            else
            {
                StringBuffer sbDebug = new StringBuffer("Invalid requestorpool specific '");
                sbDebug.append(propertyName);
                sbDebug.append("' property found for requestorpool with ID '");
                sbDebug.append(pool.getID());
                sbDebug.append("': ");
                sbDebug.append(value);
                _systemLogger.error(sbDebug.toString());
            }
        }
        else
        {
            StringBuffer sbDebug = new StringBuffer("No (optional) requestorpool specific '");
            sbDebug.append(propertyName);
            sbDebug.append("' property found for requestorpool with ID: ");
            sbDebug.append(pool.getID());
            _systemLogger.debug(sbDebug.toString());
        }
        
        return _bShowAlways; 
    }
}