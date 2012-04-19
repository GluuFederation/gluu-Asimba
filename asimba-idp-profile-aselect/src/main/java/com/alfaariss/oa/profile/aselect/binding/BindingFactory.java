
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
package com.alfaariss.oa.profile.aselect.binding;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.profile.aselect.binding.protocol.cgi.CGIBinding;

/**
 * Binding factory.
 *
 * Supports CGI binding.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class BindingFactory
{
    private static Log _logger;
    
    /**
     * Creates the object instance.
     */
    public BindingFactory()
    {
        _logger = LogFactory.getLog(BindingFactory.class);
    }

    /**
     * Returns the binding object specified by the request.
     * 
     * @param oServletRequest The servlet request object.
     * @param oServletResponse The servlet response object.
     * @return IBinding: CGIBinding
     * @throws BindingException if binding creation fails.
     */
    public IBinding getBinding(HttpServletRequest oServletRequest, 
        HttpServletResponse oServletResponse) throws BindingException
    {
        IBinding oBinding = null;
        String sMethod = oServletRequest.getMethod();
        try
        {
            if (sMethod.equalsIgnoreCase("GET"))
            {            
                //PROTOCOL_CGI;
                oBinding = new CGIBinding(oServletRequest, oServletResponse);
            }
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during binding creation", e);
            throw new BindingException(SystemErrors.ERROR_INTERNAL);
        }
        
        return oBinding;
    }

}