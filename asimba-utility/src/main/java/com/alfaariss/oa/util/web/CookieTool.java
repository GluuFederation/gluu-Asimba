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
package com.alfaariss.oa.util.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Cookie support functionality.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class CookieTool
{
    private Log _logger;
    
    /** Configured Cookie Secure */
    private boolean _bSecureCookie;
    /** Configured Cookie Domain */
    private String _sCookieDomain;
    /** Configured Cookie Version */
    private int _iCookieVersion;
        
    /**
     * Constructor. 
     * @param configurationManager The configuration manager
     * @param config The cookie configuration
     * @throws OAException 
     */
    public CookieTool(IConfigurationManager configurationManager, 
        Element config) throws OAException
    {
        _logger = LogFactory.getLog(CookieTool.class);
        
        _bSecureCookie = false;
        _sCookieDomain = null;
        _iCookieVersion = -1;
        
        readCookieConfiguration(configurationManager, config);
    }


     /* 
     *<pre>
     *               .---. .---. 
     *              :     : o   :    Me Lost Me Cookie At The Disco!
     *          _..-:   o :     :-.._    /
     *      .-''  '  `---' `---' "   ``-.    
     *    .'   "   '  "  .    "  . '  "  `.  
     *   :   '.---.,,.,...,.,.,.,..---.  ' ;
     *   `. " `.                     .' " .'
     *    `.  '`.                   .' ' .'
     *     `.    `-._           _.-' "  .'  .----.
     *       `. "    '"--...--"'  . ' .'  .'  o   `.
     *       .'`-._'    " .     " _.-'`. :       o  :
     *     .'      ```--.....--'''    ' `:_ o       :
     *   .'    "     '         "     "   ; `.;";";";'
     *  ;         '       "       '     . ; .' ; ; ;
     * ;     '         '       '   "    .'      .-'
     * '  "     "   '      "           "    _.-'
     *
     *</pre>
     */
    /**
     * Set a cookie.
     * @param sCookie The cookie name.
     * @param sValue The cookie value.
     * @param oRequest The Servlet request.
     * @return The created cookie.
     */
    public Cookie createCookie(String sCookie, String sValue, 
        HttpServletRequest oRequest)
    {       
    	return createCookie(sCookie, sValue, null, oRequest);
    }


    /**
     * Set Cookie with optional extra context in application context
     * @param sCookie
     * @param sValue
     * @param sExtraContext
     * @param oRequest
     * @return
     */
    public Cookie createCookie(String sCookie, String sValue, String sExtraContext, 
            HttpServletRequest oRequest)
    {
        assert sValue != null : "Supplied value == null";
        assert oRequest != null : "Supplied request == null";
        
        Cookie cookie = new Cookie(sCookie, sValue);
        if (_sCookieDomain != null)
        {
            cookie.setDomain(_sCookieDomain);
            _logger.debug("Created domain cookie on " + _sCookieDomain);
        }
        
        if (_iCookieVersion != -1)
        {
            cookie.setVersion(_iCookieVersion);
            _logger.debug("Setting cookie version: " + _iCookieVersion);
        }
        
        /* format sExtraContext */
        if (sExtraContext == null) {
        	sExtraContext = "";
        } else {
        	if (! sExtraContext.startsWith("/")) {
        		sExtraContext = "/" + sExtraContext;
        	}
        }
        
        String path = oRequest.getContextPath();
        if (path != null && path.length() > 0)
        {//only set path if path not is empty (when hosted as server root, getContextPath() will return an empty string)
            cookie.setPath(path + sExtraContext);// /openaselect
        }
        else
        {//if no contextpath available then setting the cookie path on '/' instead of on the default path (which is for the sso cookie: /openaselect/sso)
            cookie.setPath("/" + sExtraContext);
        }
        
        cookie.setSecure(_bSecureCookie);
        
        StringBuffer sbDebug = new StringBuffer("Created '");
        sbDebug.append(sCookie);
        sbDebug.append("' on path=");
        sbDebug.append(cookie.getPath());
        _logger.debug(sbDebug.toString());
        
        return cookie;    }
    
    
    /**
     * Returns the cookie value.
     * @param sCookie The cookie name.
     * @param oRequest The servlet request.
     * @return The cookie value or NULL if not available.
     */
    public String getCookieValue(String sCookie, HttpServletRequest oRequest) 
    {
        assert oRequest != null : "Supplied request == null";
        
        String sValue = null;    
        Cookie[] cookies = oRequest.getCookies();        
        if (cookies != null) //Cookies found
        {          
            for (Cookie cookie : cookies) //For all cookies
            {
                if (cookie.getName().equals(sCookie)) //cookie found
                {
                    sValue = cookie.getValue();
                    //remove '"' surrounding cookie value if applicable
                    int iLength = sValue.length();
                    if(sValue.charAt(0) == '"' &&
                        sValue.charAt(iLength-1) == '"')
                    {
                        sValue = sValue.substring(1, iLength-1);
                    }
                }
            }
        }
        return sValue;
    } 
    
    /**
     * Remove cookie.
     * @param sCookie The cookie name.
     * @param oRequest The servlet request.
     * @param oResponse The servlet response.
     */
    public void removeCookie(String sCookie, HttpServletRequest oRequest, 
        HttpServletResponse oResponse)
    {      
        Cookie cookie =  createCookie(sCookie, "jimmorrisonisstillalive", oRequest);  
        cookie.setMaxAge(0); //Expire                        
        oResponse.addCookie(cookie);
    }
    
    //Read optional cookie configuration
    private void readCookieConfiguration(IConfigurationManager 
        configurationManager, Element eConfig) throws OAException
    {
        assert eConfig != null : "Supplied config == null";
        
        Element eCookie = configurationManager.getSection(eConfig, "cookie");
        if(eCookie == null)
        {
            _bSecureCookie = false;
            _sCookieDomain = null;
            _logger.info(
                "No cookie configuration found, using defaults: no domain, secure not forced");
        } 
        else
        {
            String sDomain = configurationManager.getParam(eCookie, "domain");
            if(sDomain != null && sDomain.length() > 0)
            {
                _sCookieDomain = sDomain;
                _logger.info("The following cookie domain will be used for setting SSO cookies: " 
                    + _sCookieDomain);
            }
            else
            {
                _sCookieDomain = null;
                _logger.info("No specific cookie domain configuration found");
            }
            
            String sVersion = configurationManager.getParam(eCookie, "version");
            if (sVersion != null)
            {
                try
                {
                    _iCookieVersion = Integer.parseInt(sVersion);
                }
                catch (NumberFormatException e)
                {
                    _logger.error("Invalid value for 'version' item found in configuration (must be a number): " 
                        + sVersion, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (_iCookieVersion < 0)
                {
                    _logger.error("Invalid value for 'version' item found in configuration (must be >= 0): " 
                        + sVersion);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                _logger.info("Using cookie version: " + _iCookieVersion);
            }
            
            _bSecureCookie = false;
            String sSecure = configurationManager.getParam(eCookie, "secure");
            if (sSecure != null)
            {
                if("true".equalsIgnoreCase(sSecure))
                    _bSecureCookie = true;
                else if (!"false".equalsIgnoreCase(sSecure))
                {
                    _logger.error("Invalid value for 'secure' item found in configuration: " 
                        + sSecure);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            _logger.info("Optional 'secure' item is configured with value: " 
                + _bSecureCookie);
        }         
    }
}
