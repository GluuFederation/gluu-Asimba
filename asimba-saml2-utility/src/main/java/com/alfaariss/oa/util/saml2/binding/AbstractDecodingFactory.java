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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.util.DatatypeHelper;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.util.saml2.binding.artifact.HTTPArtifactDecodingFactory;
import com.alfaariss.oa.util.saml2.binding.post.HTTPPostDecodingFactory;
import com.alfaariss.oa.util.saml2.binding.redirect.HTTPRedirectDecodingFactory;
import com.alfaariss.oa.util.saml2.binding.soap11.SOAP11DecodingFactory;

/**
 * Abstract factory for resolving and creating bindings.
 * 
 * DD The creation of decoders is implemented using the abstract factory design pattern.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public abstract class AbstractDecodingFactory extends AbstractBindingFactory
{    
    /** system logger */
    private static Log _logger = LogFactory
        .getLog(AbstractDecodingFactory.class);
    
    /**
     * The SAML2 message context.
     */
    protected SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, 
        SAMLObject> _context;
    
    /**
     * Default protected constructor.
     * @param prop The bindings configuration properties.
     */
    protected AbstractDecodingFactory(BindingProperties prop)
    {   
        super(prop);  
    }

    /**
     * Resolve and retrieve a decoding factory based on the request.
     * 
     * The factory is resolved and its message context is created based on the 
     * request.
     * 
     * @param request The request.
     * @param response The response.
     * @param prop The bindings configuration properties.
     * @return The resolved factory, or <code>null</code> if no appropriate 
     *  binding factory can be resolved.
     */
    public static AbstractDecodingFactory resolveInstance(
        HttpServletRequest request, HttpServletResponse response,
        BindingProperties prop)
    {
        AbstractDecodingFactory factory = null;
        HTTPInTransport inTransport = new HttpServletRequestAdapter(request);
                
        HTTPOutTransport outTransport = new HttpServletResponseAdapter(
            response, request.isSecure());

        // First check for artifact
        if (!DatatypeHelper.isEmpty(inTransport.getParameterValue("SAMLart")))
        {
            factory = new HTTPArtifactDecodingFactory(prop);
        }
        else
        {
            if (inTransport.getHTTPMethod().equalsIgnoreCase(
                SAMLConstants.GET_METHOD))
            {
                if (!DatatypeHelper.isEmpty(inTransport.getParameterValue(
                    "SAMLRequest"))
                    || !DatatypeHelper.isEmpty(inTransport.getParameterValue(
                        "SAMLResponse")))
                {
                    factory = new HTTPRedirectDecodingFactory(prop);
                }
                else
                    _logger.debug(
                        "No SAML request or response found in GET request");
            }
            else if (inTransport.getHTTPMethod().equalsIgnoreCase(
                SAMLConstants.POST_METHOD))
            {
                String sContextType = inTransport.getHeaderValue("Content-Type");
                
                if (!DatatypeHelper.isEmpty(inTransport.getParameterValue(
                    "SAMLRequest"))
                    || !DatatypeHelper.isEmpty(inTransport.getParameterValue(
                        "SAMLResponse")))
                {
                    factory = new HTTPPostDecodingFactory(prop);
                }
                else if (sContextType == null)
                {
                    _logger.debug("No Content-Type found");
                }
                else if (sContextType.contains("text/xml"))
                {
                   factory = new SOAP11DecodingFactory(prop);
                }
                else
                    _logger.debug(
                        "No SAML request or response found and unsupported Content-Type: " + 
                        sContextType);
            }
            else
                _logger.debug("Unsupported HTTP Method: " + 
                    inTransport.getHTTPMethod());
        }

        if (factory != null)
        {
            factory._context = new BasicSAMLMessageContext<SignableSAMLObject, 
                SignableSAMLObject, SAMLObject>();
            factory._context.setInboundMessageTransport(inTransport);
            factory._context.setOutboundMessageTransport(outTransport);
        }
        else
            _logger.debug("No factory created, possible invalid request");

        return factory;
    }

    /**
     * Create the binding factory for the given binding type. 
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
    public static AbstractDecodingFactory createInstance(
        HttpServletRequest request, HttpServletResponse response,
        String sBindingType, BindingProperties prop) throws OAException
    {
        AbstractDecodingFactory factory = null;
              
        if(sBindingType.equalsIgnoreCase(
            SAMLConstants.SAML2_ARTIFACT_BINDING_URI))
        {
            factory = new HTTPArtifactDecodingFactory(prop);
        }
        else if(sBindingType.equalsIgnoreCase(
            SAMLConstants.SAML2_POST_BINDING_URI))
        {
            factory = new HTTPPostDecodingFactory(prop);        
        }
        else if(sBindingType.equalsIgnoreCase(
            SAMLConstants.SAML2_REDIRECT_BINDING_URI))
        {
            factory = new HTTPRedirectDecodingFactory(prop);
        }
        else if(sBindingType.equalsIgnoreCase(
            SAMLConstants.SAML2_SOAP11_BINDING_URI))
        {
            factory = new SOAP11DecodingFactory(prop);
        }
        else
        {
            _logger.warn("Invalid binding type supplied: " + sBindingType);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }

        HTTPInTransport inTransport = new HttpServletRequestAdapter(request);

        HTTPOutTransport outTransport = new HttpServletResponseAdapter(
            response, request.isSecure());
        
        factory._context = new BasicSAMLMessageContext<SignableSAMLObject, 
            SignableSAMLObject, SAMLObject>();
        factory._context.setInboundMessageTransport(inTransport);
        factory._context.setOutboundMessageTransport(outTransport);

        return factory;        
    }
    
    
    /**
     * Retrieve the message context.
     * @return The message context.
     */
    public SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, 
        SAMLObject> getContext()
    {
        return _context;
    }

    /**
     * Create the SAMLMessageDecoder.
     * @return The created message decoder.
     */
    public abstract SAMLMessageDecoder getDecoder();
}
