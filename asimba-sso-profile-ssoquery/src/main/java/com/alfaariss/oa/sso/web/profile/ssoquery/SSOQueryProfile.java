/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.sso.web.profile.ssoquery;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.IService;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.sso.ISSOProfile;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.sso.web.WebSSOServlet;
import com.alfaariss.oa.sso.web.profile.ssoquery.whitelist.IWhitelist;
import com.alfaariss.oa.util.logging.RequestorEventLogItem;
import com.alfaariss.oa.util.web.CookieTool;

/**
 * Profile that verifies if the user already has single sign-on with this IdP.
 *
 * This profile only verifies if a valid SSO cookie is available, not if the 
 * TGT is still available.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class SSOQueryProfile implements ISSOProfile, IService, IAuthority
{
    /** Profile ID: ssoquery */
    public final static String PROFILE_ID = "ssoquery";
    /** Request parameter: response_url */
    private final static String PARAM_RESPONSE_URL = "response_url";
    private final static String PARAM_RESULT = "result";
    
    private final static String AUTHORITY_NAME = "SSOQuery";

    private static Log _logger;
    private static Log _eventLogger;
    private boolean _bEnabled;
    private CookieTool _cookieTool;
    private ITGTFactory<?> _tgtFactory;
    private String _sProfileID;
    private IWhitelist _whitelist;
    
    /**
     * Constructor.
     */
    public SSOQueryProfile()
    {
        _logger = LogFactory.getLog(SSOQueryProfile.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
        _bEnabled = false;
    }
    
    /**
     * @see com.alfaariss.oa.api.sso.ISSOProfile#destroy()
     */
    public void destroy()
    {
        _bEnabled = false;
        _cookieTool = null;
        if (_whitelist != null)
            _whitelist.stop();
    }

    /**
     * @see com.alfaariss.oa.api.sso.ISSOProfile#getID()
     */
    public String getID()
    {
        return _sProfileID;
    }

    /**
     * @param eSpecific can be supplied as NULL
     * @see com.alfaariss.oa.api.sso.ISSOProfile#init(javax.servlet.ServletContext, com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element, org.w3c.dom.Element)
     */
    public void init(ServletContext context,
        IConfigurationManager configurationManager, Element eParent, 
        Element eSpecific) throws OAException
    {
        _bEnabled = true;
        _sProfileID = PROFILE_ID;
        
        if (eSpecific != null)
        {
            _sProfileID = configurationManager.getParam(eSpecific, "id");
            if (_sProfileID == null)
            {
                _sProfileID = PROFILE_ID;
                _logger.error("No 'id' item in 'profile' section in configuration, using default: " + _sProfileID); 
            }
            
            String sEnabled = configurationManager.getParam(eSpecific, "enabled");
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
        }
        
        if (_bEnabled)
        {
            _tgtFactory = Engine.getInstance().getTGTFactory();
            _cookieTool = new CookieTool(configurationManager, eParent);
            readWhitelistConfig(configurationManager, eSpecific);
        }
        
        _logger.info("Started SSO Query Request Profile: " + _sProfileID);
    }

    /**
     * @see com.alfaariss.oa.api.IService#service(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public void service(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) throws OAException
    {
        try
        {
            if (!_bEnabled)
            {
                _logger.debug("Component is disabled");
                throw new UserException(UserEvent.INTERNAL_ERROR);
            }
            
            _logger.debug("Performing 'sso query' request sent from IP: " 
                + servletRequest.getRemoteAddr());
            
            String responseUrl = servletRequest.getParameter(PARAM_RESPONSE_URL);
            if (responseUrl == null)
            {
                _logger.debug("No parameter '" + PARAM_RESPONSE_URL + "' available in request");
                throw new UserException(UserEvent.REQUEST_INVALID);
            }

            if (_whitelist != null)
            {
                try
                {
                    URL urlResponse = new URL(responseUrl);
                    
                    if (!_whitelist.isWhitelisted(urlResponse.getHost()))
                    {
                        _logger.debug("Hostname isn't whitelisted: " + urlResponse.getHost());
                        throw new UserException(UserEvent.REQUEST_INVALID);
                    }
                }
                catch (MalformedURLException e)
                {
                    StringBuffer sbError = new StringBuffer("Invalid parameter '");
                    sbError.append(PARAM_RESPONSE_URL);
                    sbError.append("' available in request: ");
                    sbError.append(responseUrl);
                    _logger.debug(sbError.toString());
                    
                    throw new UserException(UserEvent.REQUEST_INVALID);
                }
            }
            
            String sResult = "false";
            String sTGTCookie = _cookieTool.getCookieValue(
                WebSSOServlet.TGT_COOKIE_NAME, servletRequest);
            if (sTGTCookie != null)
            {
                ITGT tgt = _tgtFactory.retrieve(sTGTCookie);
                if (tgt != null && !tgt.isExpired())
                    sResult = "true";
            }
            
            StringBuffer sbRedirect = new StringBuffer(responseUrl);
            if (responseUrl.contains("?"))
                sbRedirect.append("&");
            else
                sbRedirect.append("?");
            
            sbRedirect.append(PARAM_RESULT);
            sbRedirect.append("=");
            sbRedirect.append(sResult);
            
            _eventLogger.info(new RequestorEventLogItem(null, sTGTCookie, 
                null, RequestorEvent.QUERY_SUCCESSFUL, null, 
                servletRequest.getRemoteAddr(), null, this, sResult));
            
            _logger.debug("Redirecting user to: " + sbRedirect.toString());
            servletResponse.sendRedirect(sbRedirect.toString());
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
        catch (Exception e)
        {
            _logger.fatal("Internal error during sso request", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * @see IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME + _sProfileID;
    }
    
    private void readWhitelistConfig(IConfigurationManager configurationManager, 
        Element config) throws OAException
    {
        _whitelist = null;
        
        Element eWhitelist = configurationManager.getSection(config, "whitelist");
        if (eWhitelist == null)
        {
            _logger.warn("No optional 'whitelist' section found in configuration");
            return;
        }
        
        String sClass = configurationManager.getParam(eWhitelist, "class");
        if (sClass == null)
        {
            _logger.error(
                "No 'class' parameter found in 'whitelist' section");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        try
        {
            Class cWhitelist = Class.forName(sClass);
            _whitelist = (IWhitelist)cWhitelist.newInstance();
        }
        catch (ClassNotFoundException e)
        {
            _logger.error(
                "Configured Whitelist class could not be found: " 
                + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);    
        }
        catch (InstantiationException e)
        {
            _logger.error(
                "Configured Whitelist class could not be instantiated: " 
                + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        catch (IllegalAccessException e)
        {
            _logger.error(
                "Configured Whitelist class could not be accessed: " 
                + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        catch (ClassCastException e)
        {
            _logger.error(
                "Configured Whitelist class isn't of type 'IWhitelist': " 
                + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }                        
       
        _whitelist.start(configurationManager, eWhitelist);
    }
}
