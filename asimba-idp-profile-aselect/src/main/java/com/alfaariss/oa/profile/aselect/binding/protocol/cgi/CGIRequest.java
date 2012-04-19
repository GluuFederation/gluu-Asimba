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
package com.alfaariss.oa.profile.aselect.binding.protocol.cgi;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.profile.aselect.binding.BindingException;
import com.alfaariss.oa.profile.aselect.binding.IRequest;

/**
 * The CGI Request object.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class CGIRequest implements IRequest
{
    private static Log _logger;
    private Hashtable<String, Object> _htRequest;
    private String _sRequestedURL;
    
    /**
     * Creates the CGI request object.
     * 
     * Reads the request parameters and puts them in a <code>Hashtable</code>
     * @param oRequest the servlet request 
     * @throws BindingException if the request object can't be created
     */
    public CGIRequest(HttpServletRequest oRequest) throws BindingException 
    {
        try
        {
            _logger = LogFactory.getLog(CGIRequest.class);
            _htRequest = new Hashtable<String, Object>();
            _sRequestedURL = oRequest.getRequestURL().toString();
            
            if (_logger.isDebugEnabled())
            {
                String sQueryString = oRequest.getQueryString();
                if (sQueryString == null)
                    sQueryString = "";
                _logger.debug("QueryString: " + sQueryString);
            }
            
            Hashtable<String, Vector<String>> htVectorItems = 
                new Hashtable<String, Vector<String>>();
            Enumeration enumNames = oRequest.getParameterNames();
            while(enumNames.hasMoreElements())
            {
                String sName = (String)enumNames.nextElement();
                String sValue = oRequest.getParameter(sName);
                if (sName.endsWith(CGIBinding.ENCODED_BRACES) 
                    || sName.endsWith(CGIBinding.ENCODED_BRACES.toLowerCase())
                    || sName.endsWith("[]"))
                {
                    Vector<String> vValues = htVectorItems.get(sName);
                    if (vValues == null)
                        vValues = new Vector<String>();
                    vValues.add(sValue);
                    htVectorItems.put(sName, vValues);
                }
                else
                    _htRequest.put(sName, sValue);
            }
            
            _htRequest.putAll(htVectorItems);
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during CGI Request creation", e);
            throw new BindingException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Returns the value of the requested parameter.
     * @see IRequest#getParameter(java.lang.String)
     */
    public Object getParameter(String sName) throws BindingException
    {
        return _htRequest.get(sName);
    }

    /**
     * Returns the requested URL.
     * 
     * The URL is the value of the method <code>getRequestURL()</code> of the 
     * servlet request.
     * @see IRequest#getRequestedURL()
     */
    public String getRequestedURL()
    {
        return _sRequestedURL;
    }

}
