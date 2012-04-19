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
package com.alfaariss.oa.util.web;

import java.io.IOException;
import java.text.StringCharacterIterator;
import java.util.StringTokenizer;

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
 * Servlet specification remote IP address Filter. 
 * 
 * This servlet extracts the remote address of the caller using 
 * {@link ServletRequest#getRemoteAddr()} and denies access if it does not 
 * match the configured comma separate wild card mask(s).
 * 
 * @author Alfa & Ariss
 * @author Erwin van den Beld
 * @version 1.0
 * 
 */
public class RemoteAddrFilter implements Filter
{   
    /** The system logger. */
    private static Log _logger = LogFactory.getLog(RemoteAddrFilter.class);      
    /** The name of the filter */
    private String _sFilterName;
    /** configured comma separated wild card mask. */
    private String _sIP;

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
                _sFilterName = RemoteAddrFilter.class.getSimpleName();
            
            //Read allowed IP from parameter
            _sIP = oFilterConfig.getInitParameter("allow");
            if(_sIP == null)
            {
                _logger.error(
                    "No 'allow' init parameter found in filter configuration");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            _sIP = _sIP.trim();
            
            StringTokenizer st = new StringTokenizer(_sIP, ",");
            if(st.countTokens() < 1)
            {
                _logger.error("Invalid 'allow' init parameter found in filter configuration");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            _logger.info("Only allowing requests from: " + _sIP);
            
            _logger.info(_sFilterName + " started");                       	       
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
     * This method only passes on the request to the chain if the remote address
     * of the caller is allowed.
     * 
     * The remote address is compared against a configured comma separate list
     * of wild card masks.
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
                _logger.warn("received a non HTTP request");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }   
            
            String remoteAdr = oHttpRequest.getRemoteAddr();    
            boolean allow = false;
            StringTokenizer st = new StringTokenizer(_sIP, ",");
            while(st.hasMoreTokens() && !allow) //For all masks
            {
                allow = matchWildcard(remoteAdr, st.nextToken().trim());
            }
            
            if(!allow) //FORBIDDEN
            {
                _logger.warn("Request not accepted from: " + remoteAdr);
                oHttpResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
            else //ALLOW
            {     
                _logger.debug("Request accepted from: " + remoteAdr);
                //Continue with chain
                oChain.doFilter(oRequest, oResponse);
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
    
    /*
     * Compare a <code>String</code> using a wild card mask.
     *  
     * @param s The <code>String</code> to be compared.
     * @param sMask The mask to compare against.
     * @return <code>true</code> if the given string matches the mask.
     */
    private static boolean matchWildcard(String s, String sMask)
    {
        //check empty string
        if (s.length() == 0)
        {
            if (sMask.length() == 0 || sMask.equals("*") || sMask.equals("?"))
                return true;
            return false;
        }

        char ch;
        int i = 0;
        StringCharacterIterator iter = new StringCharacterIterator(sMask);

        for (ch = iter.first(); ch != StringCharacterIterator.DONE
            && i < s.length(); ch = iter.next())
        {
            if (ch == '?')
                i++;
            else if (ch == '*')
            {
                int j = iter.getIndex() + 1;
                if (j >= sMask.length())
                    return true;
                String sSubFilter = sMask.substring(j);
                while (i < s.length())
                {
                    if (matchWildcard(s.substring(i), sSubFilter))
                        return true;
                    i++;
                }
                return false;
            }
            else if (ch == s.charAt(i))
            {
                i++;
            }
            else
                return false;
        }
        return (i == s.length());
    }
}