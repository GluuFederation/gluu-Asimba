/*
 * Asimba Server
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
package com.alfaariss.oa.util.web;

import java.util.Enumeration;
import java.util.Locale;
import java.util.ResourceBundle;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Basic HTTP utilities for OA Servlets and services.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class HttpUtils
{    
    /**
     * Disable the HTTP 1.0 and HTTP 1.1 caching.
     * 
     * Sets the following headers in the response:
     * <ul>
     *  <li>protocol 'HTTP/1.0': Pragma: no-cache</li>
     *  <li>protocol 'HTTP/1.1': Cache-Control: no-store, no-cache, must-revalidate</li>
     *  <li>protocol independant: Expires: -1</li>
     * </ul>
     * 
     * @param oRequest The servlet request
     * @param oResponse The servlet repsonse
     * @see <a href="http://www.w3.org/Protocols/rfc1945/rfc1945">
     *  Hypertext Transfer Protocol -- HTTP/1.0</a>
     * @see <a href="http://www.w3.org/Protocols/rfc2616/rfc2616">
     *  Hypertext Transfer Protocol -- HTTP/1.1</a>
     */
    public static void setDisableCachingHttpHeaders(HttpServletRequest oRequest,
        HttpServletResponse oResponse)
    {
        if (oRequest.getProtocol().equalsIgnoreCase("HTTP/1.0"))
        {
            oResponse.setHeader("Pragma", "no-cache");
        }
        else if (oRequest.getProtocol().equalsIgnoreCase("HTTP/1.1"))
        {
            oResponse.setHeader("Cache-Control",
                "no-store, no-cache, must-revalidate");
        }
        //for proxy caching
        oResponse.setHeader("Expires", "-1");
    }
    
    /**
     * Returns the first language which is accepted by the client (browser).
     * If the client did not specify this with the accept-language http header 
     * it returns the base bundle without a locale.
     * This ignores the default locale specified by java. 
     * 
     * @param sBase the bundle base
     * @param oRequest The request
     * @return The specified ResourceBundle or the base bundle without a locale.
     * @since 1.1
     */
    public static ResourceBundle getRequestResourceBundle(
        String sBase, HttpServletRequest oRequest)
    {
        ResourceBundle  bundleMatch = null;
        
        Enumeration enumAccepted = oRequest.getHeaders("accept-language");
        if (enumAccepted.hasMoreElements()) 
        {
            Enumeration enumLocales = oRequest.getLocales();
            while (enumLocales.hasMoreElements())
            {
                Locale pref = (Locale)enumLocales.nextElement();
                ResourceBundle bundle =
                    ResourceBundle.getBundle(sBase, pref);
                
                Locale avail = bundle.getLocale();
                if (pref.equals(avail)) 
                {
                    bundleMatch = bundle;
                    break;
                } 
                else if (pref.getLanguage().equals(avail.getLanguage())
                    && ("".equals(avail.getCountry()) || pref.getCountry().equals(avail.getCountry())))
                {
                    bundleMatch = bundle;
                    break;
                }
            }
        }
        
        if (bundleMatch == null)
        {
            bundleMatch = ResourceBundle.getBundle(sBase, new Locale("",""));
        }
        
        return bundleMatch;
    }
}
