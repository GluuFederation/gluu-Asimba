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

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;

/**
 * Servlet specification shared secret Filter. 
 * 
 * This servlet extracts a <code>shared_secret</code> parameter from the request
 * and denies access if it does not match the configured shared secret.
 * 
 * @author Alfa & Ariss
 * @author EVB
 * @since 1.0
 */
public class SharedSecretFilter implements Filter
{   
    /** The system logger. */
    private static Log _logger = LogFactory.getLog(SharedSecretFilter.class);      
    /** The name of the filter */
    private String _sFilterName;
    /** configured shared secret. */
    private String _sharedSecret;

    /**
     * Initializes the <code>RemoteAddrFilter</code>.
     * 
     * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
     */
    public void init(FilterConfig oFilterConfig) throws ServletException
    {
        try
        {                     
            //Get filter name
            _sFilterName = oFilterConfig.getFilterName();
            if(_sFilterName == null)
                _sFilterName = SharedSecretFilter.class.getSimpleName();
            
            //Read shared secret parameter
            _sharedSecret = oFilterConfig.getInitParameter("shared_secret");
            if(_sharedSecret == null || _sharedSecret.length() <= 0)
            {
                _logger.error(
                    "No 'shared_secret' init parameter found in filter configuration");
                throw new OAException(SystemErrors.ERROR_INIT);
            }                        
            _logger.info(_sFilterName + " started.");                       	       
        }
        catch(OAException e)
        {
            _logger.fatal(_sFilterName + " start failed", e);
            throw new ServletException();
        }
        catch(Exception e)
        {         
            _logger.fatal(
                _sFilterName + " start failed due to internal error", e);            
            throw new ServletException();
        }
    }

    /**
     * This method only passes on the request to the chain if the shared secret
     * parameter matches the configured shared secret.
     * 
     * 
     * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest,
     *      javax.servlet.ServletResponse, javax.servlet.FilterChain)
     */
    public void doFilter(ServletRequest oRequest, ServletResponse oResponse,
        FilterChain oChain) throws IOException, ServletException
    {       
        HttpServletRequest oHttpRequest = null;
        HttpServletResponse oHttpResponse = null;
        
        try
        {
            // try to create Http servlet request/response
            if(oRequest instanceof HttpServletRequest)
                oHttpRequest = (HttpServletRequest)oRequest;
            else
            {
                _logger.warn("received a non HTTP request");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            if(oResponse instanceof HttpServletResponse)
                oHttpResponse = (HttpServletResponse)oResponse;
            else
            {
                _logger.warn("received a non HTTP response");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }   
            
            String sharedSecret = oHttpRequest.getParameter("shared_secret");
            if (sharedSecret != null && sharedSecret.length() > 0)
            {
                if (_sharedSecret.equals(sharedSecret) )
                {
                    
                    _logger.debug(
                        "Request accepted. Shared secret credentials accepted: " 
                        + sharedSecret);                  
                    //Continue with chain
                    oChain.doFilter(oRequest, oResponse);
                } 
                else
                {
                    _logger.warn(
                        "Request not accepted. Shared secret credentials NOT accepted: " 
                        + sharedSecret);                   
                    oHttpResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            }            
            else //FORBIDDEN
            {
                _logger.warn(
                    "Request not accepted. No Shared secret credentials supplied");                   
                oHttpResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
               
            }           
        }
        catch(OAException e)
        {
            _logger.error("Could not process request", e);
            throw new ServletException();
        }
        catch(Exception e)
        {         
            _logger.fatal(
                "Could not process request, due to internal error", e);           
            throw new ServletException();
        }                 
    }

    /**
     * Specified by interface. 
     * 
     * Has no functionality.
     * @see javax.servlet.Filter#destroy()
     */
    public void destroy()
    {
        _logger.info(
            _sFilterName + " Stopped");  
    }
}