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
package com.alfaariss.oa.util.saml2.binding;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.xml.SAMLConstants;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.util.saml2.binding.artifact.HTTPArtifactEncodingFactory;
import com.alfaariss.oa.util.saml2.binding.post.HTTPPostEncodingFactory;
import com.alfaariss.oa.util.saml2.binding.redirect.HTTPRedirectEncodingFactory;
import com.alfaariss.oa.util.saml2.binding.soap11.SOAP11EncodingFactory;

/**
 * Abstract factory for resolving and creating encoders.
 * 
 * DD The creation of encoders is implemented using the abstract factory design pattern.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public abstract class AbstractEncodingFactory extends AbstractBindingFactory
{
    /** system logger */
    private static Log _logger = LogFactory.getLog(AbstractEncodingFactory.class);
       
    /** static'ly define the supported encoding bindings */
    static final List<String> _supportedBindings = Arrays.asList(
    		SAMLConstants.SAML2_ARTIFACT_BINDING_URI,
    		SAMLConstants.SAML2_POST_BINDING_URI,
    		SAMLConstants.SAML2_REDIRECT_BINDING_URI,
    		SAMLConstants.SAML2_SOAP11_BINDING_URI);
    
    /**
     * Default protected constructor.
     * @param prop The bindings configuration properties.
     */
    protected AbstractEncodingFactory(BindingProperties prop)
    {   
        super(prop);
    }
    
    /**
     * Return the bindings that we support.
     * @return
     */
    public static List<String> getSupportedBindings() {
    	return _supportedBindings;
    }
    
    
    /**
     * Retrieve an encoding factory based on the given binding type.
     * 
     * The following binding types are supported:
     * <ul>
     *  <li>{@link SAMLConstants#SAML2_ARTIFACT_BINDING_URI}</li>
     *  <li>{@link SAMLConstants#SAML2_POST_BINDING_URI}</li>
     *  <li>{@link SAMLConstants#SAML2_REDIRECT_BINDING_URI}</li>
     *  <li>{@link SAMLConstants#SAML2_SOAP11_BINDING_URI}</li>
     * </ul>
     * 
     * @param request The request.
     * @param response The response.
     * @param sBindingType The type of binding to be used.
     * @param prop The bindings configuration properties.
     * @return The created binding factory.
     * @throws OAException If an invalid binding type is supplied.
     */
    public static AbstractEncodingFactory createInstance(
        HttpServletRequest request, HttpServletResponse response, 
        String sBindingType, BindingProperties prop) throws OAException 
    {
        AbstractEncodingFactory factory = null;
                
        if(SAMLConstants.SAML2_POST_BINDING_URI.equals(sBindingType)) 
        {
            factory = new HTTPPostEncodingFactory(prop);
        }
        else if(SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(sBindingType)) 
        {
            factory = new HTTPRedirectEncodingFactory(prop);
        }
        else if(SAMLConstants.SAML2_ARTIFACT_BINDING_URI.equals(sBindingType)) 
        {
            factory = new HTTPArtifactEncodingFactory(prop);
        }
        else if(SAMLConstants.SAML2_SOAP11_BINDING_URI.equals(sBindingType)) 
        {
            factory = new SOAP11EncodingFactory(prop);
        }
        else
        {           
            _logger.warn("Invalid binding type supplied: " + sBindingType);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return factory;
    }    
    
    /**
     * Create the SAMLMessageEncoder.
     * 
     * The created SAMLMessageEncoder can be used to encode the outbound message 
     * with help from its message context.
     *     
     * @return The created message encoder.
     * @throws OAException If creation fails.
     */
    public abstract SAMLMessageEncoder getEncoder() throws OAException;
}
