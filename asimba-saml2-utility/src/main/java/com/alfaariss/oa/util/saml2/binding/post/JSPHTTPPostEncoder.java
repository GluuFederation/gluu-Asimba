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
package com.alfaariss.oa.util.saml2.binding.post;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.BaseSAML2MessageEncoder;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.util.URLBuilder;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;

import com.alfaariss.oa.util.saml2.SAML2Constants;

/**
 * SAML2 message encoder for the HTTP Post binding.
 *
 * Encodes post messages using a JSP template instead of the Velocity template 
 * engine.
 * 
 * <br><br><i>Partitially based on sources from OpenSAML (www.opensaml.org).</i>
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class JSPHTTPPostEncoder extends BaseSAML2MessageEncoder
{    
    /** logger. */
    private Log _logger = LogFactory.getLog(JSPHTTPPostEncoder.class);
    private String _sTemplateLocation;
    
    /**
     * Default constructor.
     * @param sTemplateLocation The JSP template location.
     */
    public JSPHTTPPostEncoder(String sTemplateLocation) 
    {
        super();
        _sTemplateLocation = sTemplateLocation;
    }
    

    /**
     * Encodes the message using HTTP POST binding.
     * @see org.opensaml.ws.message.encoder.BaseMessageEncoder#doEncode(
     *  org.opensaml.ws.message.MessageContext)
     */
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
    
            SAMLMessageContext samlMsgCtx = (SAMLMessageContext) messageContext;

            SAMLObject outboundMessage = samlMsgCtx.getOutboundSAMLMessage();
            if (outboundMessage == null) 
            {
                _logger.warn("No outbound SAML message contained in message context");
                throw new MessageEncodingException(
                        "No outbound SAML message contained in message context");
            }
            
            URLBuilder urlBuilder = getEndpointURL(samlMsgCtx);
            String endpointURL = urlBuilder.buildURL();

            if (samlMsgCtx.getOutboundSAMLMessage() instanceof StatusResponseType) 
            {
                ((StatusResponseType)samlMsgCtx.getOutboundSAMLMessage()
                    ).setDestination(endpointURL);
            }

            signMessage(samlMsgCtx);
            samlMsgCtx.setOutboundMessage(outboundMessage);

            postEncode(samlMsgCtx, endpointURL);
        }
        catch(MessageEncodingException e)
        {
            throw e;
        }           
        catch(Exception e)
        {
            _logger.error("Could not encode message context", e);
            throw new MessageEncodingException(
            "Internal error while encoding");
        }
        
    }

    /**
     * Returns return {@link SAMLConstants#SAML2_POST_BINDING_URI}.
     * @see org.opensaml.common.binding.encoding.SAMLMessageEncoder#getBindingURI()
     */
    public String getBindingURI()
    {
        return SAMLConstants.SAML2_POST_BINDING_URI;
    }

    /**
     * No message confidentiality.
     * @see org.opensaml.ws.message.encoder.MessageEncoder#providesMessageConfidentiality(
     *  org.opensaml.ws.message.MessageContext)
     */
    public boolean providesMessageConfidentiality(MessageContext arg0)
        throws MessageEncodingException
    {       
        return false;
    }
    /**
     * No message integrity.
     * @see org.opensaml.ws.message.encoder.MessageEncoder#providesMessageIntegrity(
     *  org.opensaml.ws.message.MessageContext)
     */
    public boolean providesMessageIntegrity(MessageContext arg0)
        throws MessageEncodingException
    {
        return false;
    }
    
    private void postEncode(SAMLMessageContext messageContext, 
        String endpointURL) throws MessageEncodingException 
    {
       
         
        InTransport inTransport = messageContext.getInboundMessageTransport();
        HttpServletRequest request = ((HttpServletRequestAdapter)inTransport).getWrappedRequest();
        OutTransport outTransport = messageContext.getOutboundMessageTransport();
        HttpServletResponse response = ((HttpServletResponseAdapter)outTransport).getWrappedResponse();
        
        HTTPOutTransport out = (HTTPOutTransport) messageContext.getOutboundMessageTransport();
        HTTPTransportUtils.addNoCacheHeaders(out);
        HTTPTransportUtils.setUTF8Encoding(out);
        
        request.setAttribute("action", endpointURL);
        
        if(messageContext.getOutboundSAMLMessage().getDOM() == null)
        {
            marshallMessage(messageContext.getOutboundSAMLMessage());
        }
        String messageXML = XMLHelper.nodeToString(messageContext.getOutboundSAMLMessage().getDOM());

        try
        {
            String encodedMessage = Base64.encodeBytes(
                messageXML.getBytes(SAML2Constants.CHARSET), Base64.DONT_BREAK_LINES);    
           
            if (messageContext.getOutboundSAMLMessage() instanceof RequestAbstractType) 
            {
                request.setAttribute("SAMLRequest", encodedMessage);    
            } 
            else if (messageContext.getOutboundSAMLMessage() instanceof StatusResponseType) 
            {
                 request.setAttribute("SAMLResponse", encodedMessage);  
            } 
            else 
            {
                _logger.warn(
                    "Invalid outbound message, not a RequestAbstractType or StatusResponseType");
                throw new MessageEncodingException(
                        "Invalid outbound message");
            }

            String relayState = messageContext.getRelayState();
            if (checkRelayState(relayState)) 
            {
                request.setAttribute("RelayState", relayState);
            }

            RequestDispatcher oDispatcher = request.getRequestDispatcher(
                   _sTemplateLocation);
                oDispatcher.forward(request, response);
        }
        catch (UnsupportedEncodingException e)
        {           
            _logger.warn(
                "Could not encode message, charset: " 
                + SAML2Constants.CHARSET, e);   
            throw new MessageEncodingException(
                "Could not encode message", e);
        }   
        catch (ServletException e)
        {
            _logger.warn(
                "Could not process forward to JSP due to Servlet Error", e); 
            throw new MessageEncodingException(
                "Could not process forward to JSP");
        }
        catch (IOException e)
        {
            _logger.warn(
                "Could not process forward to JSP due to I/O Error", e); 
            throw new MessageEncodingException(
                "Could not process forward to JSP");
        }
    }
}