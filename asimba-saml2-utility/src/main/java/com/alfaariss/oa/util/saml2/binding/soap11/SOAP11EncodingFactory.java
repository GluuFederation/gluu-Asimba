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
package com.alfaariss.oa.util.saml2.binding.soap11;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.util.saml2.binding.AbstractEncodingFactory;
import com.alfaariss.oa.util.saml2.binding.BindingProperties;

/**
 * Create a SOAP11 encoder.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class SOAP11EncodingFactory extends AbstractEncodingFactory
{
    /** system logger */
    private static Log _logger = LogFactory.getLog(SOAP11EncodingFactory.class);
    
    /**
     * Default protected constructor.
     * @param prop The bindings configuration properties.
     */
    public SOAP11EncodingFactory(BindingProperties prop)
    {   
        super(prop);  
    }
    
    /**
     * Create an SOAP 11 encoder.
     * 
     * @see AbstractEncodingFactory#getEncoder()
     */
    @Override
    public SAMLMessageEncoder getEncoder() throws OAException
    {
        try
        {           
            return new HTTPSOAP11Encoder();
        }
        catch(Exception e)
        {
            _logger.warn("Could not create HTTPSOAP11Encoder", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);            
        }
    }

}
