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
package com.alfaariss.oa.util.saml2.binding.artifact;

import java.io.IOException;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.artifact.AbstractSAML2Artifact;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactBuilder;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.binding.encoding.BaseSAML2MessageEncoder;
import org.opensaml.saml2.core.NameID;
import org.opensaml.util.URLBuilder;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Pair;

import com.alfaariss.oa.util.saml2.SAML2Constants;

/**
 * JSP base HTTP Artifact encoder.
 * 
 * Encodes artifacts using HTTP redirect or HTTP POST using a JSP template 
 * instead of the velocity template engine.
 * 
 * <br><br><i>Partitially based on sources from OpenSAML (www.opensaml.org).</i>
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class JSPHTTPArtifactEncoder extends BaseSAML2MessageEncoder
{
    /** logger */
    private Log _logger = LogFactory.getLog(JSPHTTPArtifactEncoder.class);
    private String _sTemplateLocation;
    
    /** Use POST encoding instead of GET. */
    private boolean _bPostEncoding;
    /** Artifact map. */
    private SAMLArtifactMap _artifactMap;
    
    /**
     * Create a new <code>JSPHTTPArtifactEncoder</code> with the given template 
     * and redirect encoding.

     * @param sTemplateLocation The JSp template for POST encoding.
     * @param map The artifact map to store artifact/message bindings.
     */
    public JSPHTTPArtifactEncoder(String sTemplateLocation, SAMLArtifactMap map) 
    {
        super();    
        _bPostEncoding = false;
        _sTemplateLocation = sTemplateLocation;
        _artifactMap = map;
    }
    
    /**
     * Retrieve the post binding value.
     * @return <code>true</code> if POST encoding will be used, 
     *  otherwise <code>false</code>.
     */
    public boolean isPostEncoding() 
    {
        return _bPostEncoding;
    }

    /**
     * Set the post binding value.
     * 
     * @param post <code>true</code> if POST encoding shuld be used, 
     *  otherwise <code>false</code>.
     */
    public void setPostEncoding(boolean post) 
    {
        _bPostEncoding = post;
    }
   
    /**
     * Returns return {@link SAMLConstants#SAML2_ARTIFACT_BINDING_URI}.
     * @see org.opensaml.common.binding.encoding.SAMLMessageEncoder#getBindingURI()
     */
    public String getBindingURI()
    {
        return SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
    }
    
    /**
     * No message confidentiality.
     * @see org.opensaml.ws.message.encoder.MessageEncoder#providesMessageConfidentiality(org.opensaml.ws.message.MessageContext)
     */
    public boolean providesMessageConfidentiality(MessageContext arg0)
        throws MessageEncodingException
    {       
        return false;
    }
    /**
     * No message integrity.
     * @see org.opensaml.ws.message.encoder.MessageEncoder#providesMessageIntegrity(org.opensaml.ws.message.MessageContext)
     */
    public boolean providesMessageIntegrity(MessageContext arg0)
        throws MessageEncodingException
    {
        return false;
    }

    /**
     * Encodes the message using Artifact binding.
     * @see org.opensaml.ws.message.encoder.BaseMessageEncoder#doEncode(org.opensaml.ws.message.MessageContext)
     */
    @SuppressWarnings("unchecked")
    @Override
    protected void doEncode(MessageContext messageContext)
        throws MessageEncodingException
    {
        assert messageContext != null: 
            "messageContext is empty";
        assert messageContext.getOutboundMessageTransport() != null : 
            "outboundMessageTransport is empty";
        try
        {  
            if (!(messageContext instanceof SAMLMessageContext)) 
            {
                _logger.error("Invalid message context type:" + messageContext.getClass().getSimpleName());
                throw new MessageEncodingException(
                        "Invalid message context type");
            }
            
            if (!(messageContext.getOutboundMessageTransport() 
                instanceof HTTPOutTransport)) 
            {
                _logger.error("Invalid outbound message transport type:" 
                    + messageContext.getOutboundMessageTransport().getClass().getSimpleName());
                throw new MessageEncodingException(
                        "Invalid outbound message transport type");
            }
    
            SAMLMessageContext<SAMLObject, SAMLObject, NameID> artifactContext = 
                (SAMLMessageContext<SAMLObject, SAMLObject, NameID>) messageContext;
            HTTPOutTransport outTransport = (HTTPOutTransport) artifactContext.getOutboundMessageTransport();
            outTransport.setCharacterEncoding(SAML2Constants.CHARSET); 
    
            
            if (_bPostEncoding) 
            {
                postEncode(artifactContext, outTransport);
            } 
            else 
            {
                getEncode(artifactContext, outTransport);
            }      
        }
        catch(MessageEncodingException e)
        {
            throw e;
        }           
        catch(Exception e)
        {
            _logger.error("Could not encode messagecontext", e);
            throw new MessageEncodingException(
            "Internal error while encoding");
        }
        
    }
    
    private void postEncode(SAMLMessageContext<SAMLObject, SAMLObject, NameID> artifactContext,
        HTTPOutTransport outTransport) throws MessageEncodingException
    {       
        InTransport inTransport = artifactContext.getInboundMessageTransport();
        HttpServletRequest request = ((HttpServletRequestAdapter)inTransport).getWrappedRequest();       
        HttpServletResponse response = ((HttpServletResponseAdapter)outTransport).getWrappedResponse();
        
        request.setAttribute("action", getEndpointURL(artifactContext));
        request.setAttribute("SAMLArt", 
            buildArtifact(artifactContext).base64Encode());             

        if (checkRelayState(artifactContext.getRelayState()))
        {
            request.setAttribute("RelayState", 
                HTTPTransportUtils.urlEncode(artifactContext.getRelayState()));
        }
        try
        {
            _logger.debug("Forward caller to JSP template");
            RequestDispatcher oDispatcher = request.getRequestDispatcher(
                  _sTemplateLocation);
        
            oDispatcher.forward(request, response);
        }
        catch (ServletException e)
        {
            _logger.warn(
                "Could not process forward to JSP due to Servlet Error", e); 
            throw new MessageEncodingException("Could not process forward to JSP");
        }
        catch (IOException e)
        {
            _logger.warn(
                "Could not process forward to JSP due to I/O Error", e); 
            throw new MessageEncodingException("Could not process forward to JSP");
        }
    }

    private void getEncode(SAMLMessageContext<SAMLObject, SAMLObject, NameID> artifactContext,
        HTTPOutTransport outTransport) throws MessageEncodingException
    {
        URLBuilder urlBuilder = getEndpointURL(artifactContext);

        List<Pair<String, String>> params = urlBuilder.getQueryParams();

        params.add(new Pair<String, String>("SAMLart", buildArtifact(
            artifactContext).base64Encode()));

        if (checkRelayState(artifactContext.getRelayState()))
        {
            params.add(new Pair<String, String>("RelayState", 
                artifactContext.getRelayState()));
        }

        outTransport.sendRedirect(urlBuilder.buildURL());
    }

    private AbstractSAML2Artifact buildArtifact(
        SAMLMessageContext<SAMLObject, SAMLObject, NameID> artifactContext) throws MessageEncodingException
    {

        SAML2ArtifactBuilder<?> artifactBuilder;
        if (artifactContext.getOutboundMessageArtifactType() != null)
        {
            artifactBuilder = 
                Configuration.getSAML2ArtifactBuilderFactory().getArtifactBuilder(
                    artifactContext.getOutboundMessageArtifactType());
        }
        else
        {
            artifactBuilder = 
                Configuration.getSAML2ArtifactBuilderFactory().getArtifactBuilder(
                    SAML2ArtifactType0004.TYPE_CODE);
            artifactContext.setOutboundMessageArtifactType(
                SAML2ArtifactType0004.TYPE_CODE);
        }

        AbstractSAML2Artifact artifact = artifactBuilder.buildArtifact(artifactContext);
        String encodedArtifact = artifact.base64Encode();
        try
        {
            _artifactMap.put(encodedArtifact, 
                artifactContext.getInboundMessageIssuer(), 
                artifactContext.getOutboundMessageIssuer(), 
                artifactContext.getOutboundSAMLMessage());
        }
        catch (MarshallingException e)
        {
            _logger.error(
                "Error while marshalling assertion to be represented as an artifact",
                e);
            throw new MessageEncodingException(
                "Error while marshalling assertion");
        }
        return artifact;
    }
}
