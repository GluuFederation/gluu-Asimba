
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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.profile.aselect.binding.BindingException;
import com.alfaariss.oa.profile.aselect.binding.IBinding;
import com.alfaariss.oa.profile.aselect.binding.IRequest;
import com.alfaariss.oa.profile.aselect.binding.IResponse;

/**
 * The A-Select CGI binding object.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class CGIBinding implements IBinding
{   
    /** %5B%5D */
    public static final String ENCODED_BRACES = "%5B%5D";
    
    private Log _logger;
    private HttpServletRequest _oServletRequest;
    private HttpServletResponse _oServletResponse;
    private CGIRequest _oCGIRequest;
    
    /**
     * Creates the object. 
     * @param oServletRequest The servlet request object.
     * @param oServletResponse The servlet response object.
     * @throws BindingException if binding creation fails
     */
    public CGIBinding (HttpServletRequest oServletRequest, 
        HttpServletResponse oServletResponse) throws BindingException
    {
        try
        {
            _logger = LogFactory.getLog(CGIBinding.class);
            _oServletRequest = oServletRequest;
            _oServletResponse = oServletResponse;
            _oCGIRequest = new CGIRequest(_oServletRequest);
        }
        catch (BindingException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during CGI binding creation", e);
            throw new BindingException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Returns a CGI Request created from the supplied servlet request.
     * @see com.alfaariss.oa.profile.aselect.binding.IBinding#getRequest()
     */
    public IRequest getRequest() throws BindingException
    {
        return _oCGIRequest;
    }

    /**
     * Returns a CGI Response created from the supplied servlet response.
     * @see com.alfaariss.oa.profile.aselect.binding.IBinding#getResponse()
     */
    public IResponse getResponse() throws BindingException
    {
        return new CGIResponse(_oServletResponse);
    }

}