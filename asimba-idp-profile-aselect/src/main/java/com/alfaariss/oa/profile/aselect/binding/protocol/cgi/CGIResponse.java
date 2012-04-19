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

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.util.Vector;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.profile.aselect.binding.BindingException;
import com.alfaariss.oa.profile.aselect.binding.IResponse;
import com.alfaariss.oa.profile.aselect.processor.ASelectProcessor;

/**
 * The CGI Response object.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class CGIResponse implements IResponse
{
    private static Log _logger;
    private StringBuffer _sbResponse;
    private HttpServletResponse _servletResponse;
    
    /**
     * Creates the object from the supplied servlet response.
     * @param oResponse the servlet response 
     */
    public CGIResponse(HttpServletResponse oResponse)
    {
        _logger = LogFactory.getLog(CGIResponse.class);
        _servletResponse = oResponse;
        _sbResponse = new StringBuffer();
    }
    
    /**
     * Sends the response back to the requestor.
     * @see com.alfaariss.oa.profile.aselect.binding.IResponse#send()
     */
    public void send() throws BindingException
    {
        OutputStream oOutputStream = null;
        try
        {
            oOutputStream = _servletResponse.getOutputStream();
            oOutputStream.write(_sbResponse.toString().getBytes(
                ASelectProcessor.CHARSET));
            
            _logger.debug(_sbResponse.toString());
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during send: " + _sbResponse.toString(), e);
            throw new BindingException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {   
            try
            {
                if (oOutputStream != null)
                    oOutputStream.close();
            }
            catch (IOException e)
            {
                _logger.fatal("Internal error during send: " + _sbResponse.toString(), e);
                throw new BindingException(SystemErrors.ERROR_INTERNAL);
            }
        }
        
    }

    /**
     * Sets the supplied parameter with the supplied value.
     * Supports <code>String<code> and <code>Vector</code> objects as value.
     * The parameter names must be unique.
     * @see IResponse#setParameter(java.lang.String, java.lang.Object)
     */
    public void setParameter(String sName, Object oValue) throws BindingException
    {
        try
        {
            sName = URLEncoder.encode(sName, ASelectProcessor.CHARSET);
            
            if (_sbResponse.length() > 0)
                _sbResponse.append("&");
            
            if (oValue instanceof Vector)
            {
                StringBuffer sbEncName = new StringBuffer(sName);
                sbEncName.append(CGIBinding.ENCODED_BRACES);
                sbEncName.append("=");
                
                if (_sbResponse.indexOf(sbEncName.toString()) > -1)
                {
                    _logger.error(
                        "The response already contains an array parameter with name: " 
                        + sName);
                    throw new BindingException(SystemErrors.ERROR_INTERNAL);
                }
                
                Vector vValues = (Vector)oValue;
                for(int i = 0; i < vValues.size(); i++)
                {
                    if (i > 0)
                        _sbResponse.append("&");
                    _sbResponse.append(sbEncName.toString());
                    _sbResponse.append(URLEncoder.encode((String)vValues.get(i), 
                        ASelectProcessor.CHARSET));
                }
            }
            else
            {
                if (_sbResponse.indexOf(sName + "=") > -1)
                {
                    _logger.error(
                        "The response already contains a parameter with name: " 
                        + sName);
                    throw new BindingException(SystemErrors.ERROR_INTERNAL);
                }
                
                _sbResponse.append(sName);
                _sbResponse.append("=");
                _sbResponse.append(URLEncoder.encode((String)oValue, 
                    ASelectProcessor.CHARSET));
            }
        }
        catch (BindingException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer(
                "Internal error while setting parameter '");
            sbError.append(sName);
            sbError.append("' with value:" );
            sbError.append(oValue);
            _logger.fatal(sbError.toString(), e);
            throw new BindingException(SystemErrors.ERROR_INTERNAL);
        }
    }

}
