
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
package com.alfaariss.oa.profile.aselect.processor;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Hashtable;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IService;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.profile.IRequestorProfile;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.authentication.factory.IAuthenticationProfileFactory;
import com.alfaariss.oa.profile.aselect.ASelectErrors;
import com.alfaariss.oa.profile.aselect.ASelectException;
import com.alfaariss.oa.profile.aselect.binding.BindingFactory;
import com.alfaariss.oa.profile.aselect.binding.IBinding;
import com.alfaariss.oa.profile.aselect.binding.IRequest;
import com.alfaariss.oa.profile.aselect.logout.LogoutManager;
import com.alfaariss.oa.profile.aselect.processor.handler.BrowserHandler;
import com.alfaariss.oa.profile.aselect.processor.handler.idp.IDPHandler;
import com.alfaariss.oa.profile.aselect.processor.handler.sp.SPHandler;

/**
 * The A-Select protocol processor.
 *
 * Prosesses all incoming calls according to the A-Select protocol. 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ASelectProcessor implements IRequestorProfile, IService
{
    /** UTF-8 */
    public final static String CHARSET = "UTF-8";
    /** 256 */
    public final static int CREDENTIALS_LENGTH = 256;
    /** A-Select Profile */
    public final static String AUTHORITY_NAME = "A-Select Profile";
    
    /** app_url */
    public final static String SESSION_REQUESTOR_URL = "requestor_url";
    /** required_level */
    public final static String SESSION_REQUIRED_LEVEL = "required_level";
    /** credentials */
    public final static String SESSION_CREDENTIALS = "credentials";
    
    /** rid */
    public final static String PARAM_RID = "rid";
    /** a-select-server */
    public final static String PARAM_ASELECTSERVER = "a-select-server";
    /** aselectserver */
    public final static String PARAM_ASELECTSERVER_ALTERATIVE = "aselectserver";
    /** app_id */
    public final static String PARAM_APPID = "app_id";
    /** requestor */
    public final static String PARAM_REQUESTORID = "requestor";
    /** app_url */
    public final static String PARAM_APPURL = "app_url";
    /** as_url */
    public final static String PARAM_ASELECT_URL = "as_url";
    /** uid */
    public final static String PARAM_UID = "uid";
    /** country */
    public final static String PARAM_COUNTRY = "country";
    /** language */
    public final static String PARAM_LANGUAGE = "language";
    /** forced_logon */
    public final static String PARAM_FORCED_LOGON = "forced_logon";
    /** remote_organization */
    public final static String PARAM_REMOTE_ORGANIZATION = "remote_organization";
    /** aselect_credentials */
    public final static String PARAM_ASELECT_CREDENTIALS = "aselect_credentials";
    /** result_code */
    public final static String PARAM_RESULT_CODE = "result_code";
    /** organization */
    public final static String PARAM_ORGANIZATION = "organization";
    /** authsp */
    public final static String PARAM_AUTHSP = "authsp";
    /** authsp_level */
    public final static String PARAM_AUTHSP_LEVEL = "authsp_level";
    /** asp */
    public final static String PARAM_ASP = "asp";
    /** asp_level */
    public final static String PARAM_ASP_LEVEL = "asp_level";
    /** app_level */
    public final static String PARAM_APP_LEVEL = "app_level";
    /** tgt_exp_time */
    public final static String PARAM_TGT_EXP_TIME = "tgt_exp_time";
    /** attributes */
    public final static String PARAM_ATTRIBUTES = "attributes";
    /** signature */
    public final static String PARAM_SIGNATURE = "signature";
    /** required_level */
    public final static String PARAM_REQUIRED_LEVEL = "required_level";
    /** local_organization */
    public final static String PARAM_LOCAL_IDP = "local_organization";
    /** local_as_url */
    public final static String PARAM_LOCAL_IDP_URL = "local_as_url";
    /** reason */
    public final static String PARAM_REASON = "reason";
    /** reason value: passive */
    public final static String PARAM_PASSIVE = "passive";
    /** reason value: timeout */
    public final static String VALUE_REASON_TIMEOUT = "timeout";
    
    private static final String DEFAULT_JSP_ERROR = "/ui/profiles/aselect/error.jsp";
    private static final String DEFAULT_SSO_PATH = "/sso";
    private static final String DEFAULT_JSP_REDIRECT = "/ui/profiles/aselect/redirectreset.jsp";
    
    private String _sID;
    private Log _logger;
    private BindingFactory _bindingFactory;
    private SPHandler _oSPHandler;
    private IDPHandler _oIDPHandler;
    private BrowserHandler _oBrowserHandler;
    private LogoutManager _oLogoutHandler;
    private IConfigurationManager _configurationManager;
    private String _sJSPError;
    private String _sRedirectJspPath;
    private boolean _bLocalErrorHandling;
    private String _sWebSSOPath;
    private String _sWebSSOURL;

    /**
     * Creates the object.
     */
    public ASelectProcessor()
    {
        _logger = LogFactory.getLog(ASelectProcessor.class);
        _bindingFactory = new BindingFactory();
    }

    /**
     * Processes the incoming calls.
     *
     * Supports the following A-Select calls:
     * <br><br>
     * A-Select SP (application) interface (if enabled)
     * <ul>
     * <li>authenticate : <code>request=authenticate</code></li>
     * <li>verify credentials : <code>request=verify_credentials</code></li>
     * <li>logout : no 'request' and no 'rid'</li>
     * </ul>
     * A-Select IDP (Cross A-Select) interface (if enabled)
     * <ul> 
     * <li>authenticate: <code>request=authenticate&local_organization=[local_organization]</code></li>
     * <li>verify credentials: <code>request=verify_credentials&local_organization=[local_organization]</code></li>
     * </ul>
     * User interface
     * <ul>
     * <li>login redirect: <code>request=login1</code></li>
     * <li>authentication response initiated by the Web SSO: no 'request' and 'rid'</li>
     * </ul>
     * 
     * @see IService#service(javax.servlet.http.HttpServletRequest, 
     *     javax.servlet.http.HttpServletResponse)
     */
    public void service(HttpServletRequest oServletRequest,
        HttpServletResponse oServletResponse) throws OAException
    {
        try
        {
            IBinding oBinding = _bindingFactory.getBinding(oServletRequest, oServletResponse);
            if (oBinding == null)
            {
                _logger.error(
                    "Invalid request sent from IP: " + oServletRequest.getRemoteAddr());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            IRequest oRequest = oBinding.getRequest();
  
            String sLocalOrganization = (String)oRequest.getParameter(PARAM_LOCAL_IDP);
            String sAppID = (String)oRequest.getParameter(PARAM_APPID);
            String sRequestorID = (String)oRequest.getParameter(PARAM_REQUESTORID);
            String sASelectCredentials = (String)oRequest.getParameter(PARAM_ASELECT_CREDENTIALS);
            String sRID = (String)oRequest.getParameter(PARAM_RID);
            
            String sRequest = (String)oRequest.getParameter("request");
            if (sRequest == null && sRID != null)
            {
                _logger.debug("Performing Browser request initiated by the Web SSO sent from IP: " 
                    + oServletRequest.getRemoteAddr());
                _oBrowserHandler.authenticate(oServletRequest, oServletResponse, oBinding);
            }
            else if (sRequest == null && sRID == null)
            {
                _logger.debug("Performing user information Browser request sent from IP: " 
                    + oServletRequest.getRemoteAddr());
                _oBrowserHandler.userinformation(oServletRequest, oServletResponse);
            }
            else if (sRequest == null)
            {
                _logger.error("No request parameter found in sent from IP: " 
                    + oServletRequest.getRemoteAddr());
                
                throw new ASelectException(ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            else if (sRequest.equals("authenticate") 
                && _oIDPHandler.isEnabled() 
                && sLocalOrganization != null)
            {
                _logger.debug("Performing 'authenticate' IDP request sent from IP: " 
                    + oServletRequest.getRemoteAddr());
                _oIDPHandler.authenticate(oServletRequest, oBinding);
            }
            else if (sRequest.equals("authenticate")
                && _oSPHandler.isEnabled())
            {
                _logger.debug("Performing 'authenticate' SP request sent from IP: " 
                    + oServletRequest.getRemoteAddr());
                _oSPHandler.authenticate(oServletRequest, oBinding);
            }
            else if(sRequest.equals("verify_credentials") 
                && _oIDPHandler.isEnabled() 
                && sLocalOrganization != null)
            {
                _logger.debug("Performing 'verify_credentials' IDP request sent from IP: " 
                    + oServletRequest.getRemoteAddr());
                _oIDPHandler.verifyCredentials(oServletRequest, oBinding);
            }
            else if(sRequest.equals("verify_credentials"))
            {
                _logger.debug("Performing 'verify_credentials' SP request sent from IP: " 
                    + oServletRequest.getRemoteAddr());
               _oSPHandler.verifyCredentials(oServletRequest, oBinding);
            }
            else if(sRequest.equals("login1"))
            {
                _logger.debug("Performing 'login1' Browser request sent from IP: " 
                    + oServletRequest.getRemoteAddr());
                _oBrowserHandler.login1(oServletRequest, oServletResponse, oBinding);
            }
            else if(sRequest.equals("logout") && sASelectCredentials != null 
                && sLocalOrganization != null)
            {//synchronous logout
                if (_oIDPHandler.isEnabled() )
                {
                    _logger.debug("Performing 'synchronous logout' request sent from IP: " 
                        + oServletRequest.getRemoteAddr());
                    _oIDPHandler.doOrganizationSynchronousLogout(oServletRequest, oBinding, 
                        sLocalOrganization, sASelectCredentials);
                }   
                else
                    _logger.debug("Could not process request: IDP handler disabled");
            }
            else if(sRequest.equals("logout") && sASelectCredentials != null
                && (sAppID != null || sRequestorID != null))
            {//synchronous logout
                if (_oSPHandler.isEnabled())
                {
                    _logger.debug("Performing 'synchronous logout' request sent from IP: " 
                        + oServletRequest.getRemoteAddr());
                    _oSPHandler.doRequestorSynchronousLogout(oServletRequest, oBinding, 
                        sRequestorID, sAppID, sASelectCredentials);
                }
                else
                    _logger.debug("Could not process request: SP handler disabled");
            }
            else if(sRequest.equals("logout") 
                && sRID != null)
            {//asynchronous logout
                _logger.debug("Performing 'asynchronous logout' Browser request sent from IP: " 
                    + oServletRequest.getRemoteAddr());
                _oBrowserHandler.logout(oServletRequest, oServletResponse, oBinding);
            }
            else if(sRequest.equals("slo") && sLocalOrganization != null)
            {//asynchronous logout
                if (_oIDPHandler.isEnabled())
                {
                    _logger.debug("Performing 'asynchronous init logout' IDP request sent from IP: " 
                        + oServletRequest.getRemoteAddr());
                    _oIDPHandler.slo(oServletRequest, oBinding);
                }   
                else
                    _logger.debug("Could not process request: IDP handler disabled");
            }
            else if(sRequest.equals("slo"))
            {//asynchronous logout
                if (_oSPHandler.isEnabled())
                {
                    _logger.debug("Performing 'asynchronous init logout' SP request sent from IP: " 
                        + oServletRequest.getRemoteAddr());
                    _oSPHandler.slo(oServletRequest, oBinding);
                }
                else
                    _logger.debug("Could not process request: SP handler disabled");
            }
            else
            {
                if (_logger.isDebugEnabled())
                {
                    if (_oSPHandler != null)
                        _logger.debug("SP Handler enabled: " + _oSPHandler.isEnabled());
                    
                    if (_oIDPHandler != null)
                        _logger.debug("IDP Handler enabled: " + _oIDPHandler.isEnabled());
                }
                
                //TODO replace by event and debug logging (EVB, MHO)
                StringBuffer sbWarning = new StringBuffer("Invalid request with name: ");
                sbWarning.append(sRequest);
                sbWarning.append(", sent from IP: ");
                sbWarning.append(oServletRequest.getRemoteAddr());
                _logger.error(sbWarning.toString());
                
                throw new ASelectException(ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
        }
        catch (ASelectException e)
        {
            try
            {
                if (!oServletResponse.isCommitted())
                    oServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
            catch (IOException e1)
            {
              _logger.warn("Could not send response", e1);
            }
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during request process", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Starts the A-Select processor. 
     * @see IRequestorProfile#init(javax.servlet.ServletContext, 
     *  IConfigurationManager, org.w3c.dom.Element)
     */
    public void init(ServletContext context, 
        IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException
    {
        try
        {
            _configurationManager = oConfigurationManager;
           
            _sID = _configurationManager.getParam(eConfig, "id");
            if (_sID == null)
            {
                _logger.error("No 'id' parameter found in 'profile' section");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sRedirectURL = oConfigurationManager.getParam(
                eConfig, "redirect_url");
            if (sRedirectURL == null)
            {
                _logger.info("No optional 'redirect_url' parameter found in 'profile' section with id='aselect' in configuration");
            }
            else
            {
                try
                {
                    new URL(sRedirectURL);
                }
                catch (MalformedURLException e)
                {
                    _logger.error("The supplied 'redirect_url' parameter isn't an URL: " 
                        + sRedirectURL, e);
                    
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                _logger.info("Using configured 'redirect_url' parameter: " + sRedirectURL);
            }
            
            Element eRedirectJSP = oConfigurationManager.getSection(
                eConfig, "redirectreset_jsp");
            if (eRedirectJSP == null)
            {
                _logger.info("No optional 'redirectreset_jsp' parameter found in 'profile' section with id='aselect' in configuration, using default");
                _sRedirectJspPath = DEFAULT_JSP_REDIRECT;
            }
            else
            {
                _sRedirectJspPath = oConfigurationManager.getParam(eRedirectJSP, "path");
                if (_sRedirectJspPath == null)
                {
                    _logger.error("No 'path' parameter found in 'redirectreset_jsp' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                _logger.info("Using configured redirect reset JSP: " + _sRedirectJspPath);
            }
            
            readConfigError(oConfigurationManager, eConfig);
            
            readConfigWebSSO(oConfigurationManager, eConfig);
            
            _oBrowserHandler = new BrowserHandler(sRedirectURL, _sWebSSOPath, 
                _sWebSSOURL, _sJSPError, _bLocalErrorHandling, _sID, 
                _sRedirectJspPath);
            
            Element eAuthentication = oConfigurationManager.getSection(eConfig, "authentication");
            if (eAuthentication == null)
            {
                _logger.error("No 'authentication' section found in 'profile' section with id='aselect' in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sDefaultAuthSPLevel = oConfigurationManager.getParam(eAuthentication, "authsp_level");
            if (sDefaultAuthSPLevel == null)
            {
                _logger.error("No default 'authsp_level' item in 'profile' section with id='aselect' found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            int iDefaultAuthSPLevel = -1;
            try
            {
                iDefaultAuthSPLevel = Integer.parseInt(sDefaultAuthSPLevel);
            }
            catch(NumberFormatException e)
            {
                _logger.error("Invalid default 'authsp_level' item found in configuration: " 
                    + sDefaultAuthSPLevel, e);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            _logger.info("Configured default 'authsp_level': " + sDefaultAuthSPLevel);
            
            Hashtable<String, Integer> htAuthSPLevels = readConfigAuthNLevels(oConfigurationManager, eAuthentication);
            
            Element eRequesthandlers = _configurationManager.getSection(
                eConfig, "requesthandlers");
            if (eRequesthandlers == null)
            {
                _logger.error("No 'requesthandlers' section found in 'profile' section with id='aselect' in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eSP = _configurationManager.getSection(eRequesthandlers, "sp");
            if (eSP == null)
                _logger.warn("No optional 'sp' section found in 'requesthandlers' section in configuration");
            _oSPHandler = new SPHandler(_configurationManager, eSP, sRedirectURL, htAuthSPLevels, iDefaultAuthSPLevel, _sID);
            
            Element eIDP = _configurationManager.getSection(eRequesthandlers, "idp");
            if (eIDP == null)
                _logger.warn("No optional 'idp' section found in 'requesthandlers' section in configuration");
            _oIDPHandler = new IDPHandler(_configurationManager, eIDP, sRedirectURL, htAuthSPLevels, iDefaultAuthSPLevel, _sID);
            
            Element eLogout = _configurationManager.getSection(eConfig, "logout");
            _oLogoutHandler = new LogoutManager(_sID, _configurationManager, eLogout);
            if (_oLogoutHandler.isEnabled())
            {
                Engine.getInstance().getTGTFactory().addListener(_oLogoutHandler);
                _logger.info("Outgoing synchronous logout: enabled");
            }
            else
            {
                _logger.info("Outgoing synchronous logout: disabled");
                _oLogoutHandler = null;
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during request process", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Stops the A-Select processor. 
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public void destroy()
    {
        if (_oLogoutHandler != null)
        {
            try
            {
                Engine.getInstance().getTGTFactory().removeListener(_oLogoutHandler);
            }
            catch (OAException e)
            {
                _logger.error("Could not remove the logout handler as TGT listener", e);
            }
        }
        
        _oIDPHandler = null;
        _oSPHandler = null;
        _oBrowserHandler = null;
    }
    
    /**
     * @see com.alfaariss.oa.api.profile.IRequestorProfile#getID()
     */
    public String getID()
    {
        return _sID;
    }

    
    private void readConfigError(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException
    {
        _bLocalErrorHandling = false;
        _sJSPError = DEFAULT_JSP_ERROR;
        
        Element eError = oConfigurationManager.getSection(eConfig, "error");
        if (eError == null)
        {
            _logger.warn("No optional 'error' section found in 'profile' section with id='" + _sID + "' in configuration, using defaults");
        }
        else
        {
            Element eJsp = oConfigurationManager.getSection(eError, "jsp");
            if (eJsp == null)
            {
                _logger.warn("No optional 'jsp' section found in 'error' section in configuration, using defaults");
            }
            else
            {
                _sJSPError = oConfigurationManager.getParam(eJsp, "path");
                if (_sJSPError == null)
                {
                    _logger.error("No 'path' parameter found in 'jsp' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            
            Element eHandling = oConfigurationManager.getSection(eError, "handling");
            if (eHandling != null)
            {
                String sLocal = oConfigurationManager.getParam(eHandling, "local");
                if (sLocal == null)
                {
                    _logger.error("No 'local' parameter found in 'handling' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                if (sLocal.equalsIgnoreCase("true"))
                {
                    _bLocalErrorHandling = true;
                }
                else if (!sLocal.equalsIgnoreCase("false"))
                {
                    _logger.error("Wrong 'local' parameter found in 'handling' section in configuration; must be TRUE or FALSE: " 
                        + sLocal);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
        }
        
        _logger.info("Using local error handling: " + _bLocalErrorHandling);
        _logger.info("Using error handling: " + _sJSPError);
    }
    
    private Hashtable<String, Integer> readConfigAuthNLevels(IConfigurationManager oConfigurationManager, 
        Element eAuthentication) throws OAException
    {
        IAuthenticationProfileFactory authNProfileFactory = Engine.getInstance().getAuthenticationProfileFactory();
        
        Hashtable<String, Integer> htAuthSPLevels = new Hashtable<String, Integer>();
        Element eAuthNProfile = oConfigurationManager.getSection(eAuthentication, "profile");
        while (eAuthNProfile != null)
        {
            String sAuthNProfileID = oConfigurationManager.getParam(eAuthNProfile, "id");
            if (sAuthNProfileID == null)
            {
                _logger.error("No 'id' item in 'profile' section found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            if (authNProfileFactory.getProfile(sAuthNProfileID) == null)
            {
                _logger.error("The configured 'id' doesn't exist as an authentication profile: " 
                    + sAuthNProfileID);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            String sAuthSPLevel = oConfigurationManager.getParam(eAuthNProfile, "authsp_level");
            if (sAuthSPLevel == null)
            {
                _logger.error("No 'authsp_level' item in 'profile' section found in configuration for profile id: " 
                    + sAuthNProfileID);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Integer intAuthSPLevel = null;
            try
            {
                intAuthSPLevel = Integer.parseInt(sAuthSPLevel);
            }
            catch(NumberFormatException e)
            {
                StringBuffer sbError = new StringBuffer("Invalid 'authsp_level' item in 'profile' section found in configuration for profile id '");
                sbError.append(sAuthNProfileID);
                sbError.append("' level isn't a number: ");
                sbError.append(sAuthSPLevel);
                _logger.error(sbError.toString(), e);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            if (htAuthSPLevels.containsKey(sAuthNProfileID))
            {
                _logger.warn("The configured authentication profile doesn't have an unique id: " 
                    + sAuthNProfileID);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            htAuthSPLevels.put(sAuthNProfileID, intAuthSPLevel);
            StringBuffer sbInfo = new StringBuffer("Configured: authsp_level=");
            sbInfo.append(sAuthSPLevel);
            sbInfo.append(" for authentication profile with id: ");
            sbInfo.append(sAuthNProfileID);
            _logger.info(sbInfo.toString());
            
            eAuthNProfile = oConfigurationManager.getNextSection(eAuthNProfile);
        }
        
        return htAuthSPLevels;
    }
    
    private void readConfigWebSSO(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException
    {
        _sWebSSOPath = DEFAULT_SSO_PATH;
        _sWebSSOURL = null;
        
        Element eWebSSO = oConfigurationManager.getSection(eConfig, "websso");
        if (eWebSSO == null)
        {
            _logger.warn("No optional 'websso' section found in 'profile' section with id='" + _sID + "' in configuration, using defaults");
        }
        else
        {
            String sWebSSOPath = oConfigurationManager.getParam(eWebSSO, "path");
            if (sWebSSOPath == null)
            {
                _logger.warn("No optional 'path' parameter found in 'websso' section in configuration, using default");
            }
            
            String sWebSSOUrl = oConfigurationManager.getParam(eWebSSO, "url");
            if (sWebSSOUrl == null)
            {
                _logger.warn("No optional 'url' parameter found in 'websso' section in configuration, only using forwards");
            }
            else
                _logger.info("Using configured WebSSO URL: " + sWebSSOUrl);
        }
        
        _logger.info("Using configured WebSSO path: " + _sWebSSOPath);
    }
}