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

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;

import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Fault;
import org.opensaml.ws.soap.soap11.FaultCode;
import org.opensaml.ws.soap.soap11.FaultString;
import org.opensaml.ws.soap.soap11.impl.BodyBuilder;
import org.opensaml.ws.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.ws.soap.soap11.impl.FaultBuilder;
import org.opensaml.ws.soap.soap11.impl.FaultCodeBuilder;
import org.opensaml.ws.soap.soap11.impl.FaultStringBuilder;
import org.opensaml.ws.soap.util.SOAPConstants;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.util.saml2.SAML2Constants;

/**
 * Utilities for the SOAP11 binding.
 *
 * SOAP processing Faults should be handled by binding encoders/decoders 
 * conform the SAML binding specification. Because open SAML does not send SOAP 
 * faults for SOAP processing errors or invalid SOAP requests this utility class 
 * can be used.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class SOAP11Utils
{   
    private static Log _logger = LogFactory.getLog(SOAP11Utils.class);
    
    /**
     * Construct and send a SOAP Fault.
     *
     * Constructs a SOAP Fault message and send it using the out transport of
     * the message context.
     * 
     * The followinf SOAP codes are send:
     * <dl>
     *  <dt>soap11:Client</dt>
     *      <dd>In case of a {@link RequestorEvent#REQUEST_INVALID}</dd>
     *  <dt>soap11:Server</dt>
     *      <dd>In case of other {@link RequestorEvent}s</dd>   
     * </dl>
     * 
     * @param messageContext The message context.
     * @param event The requestor event.
     * @throws OAException If sending fails due to internal error.
     */
    public static void sendSOAPFault(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> messageContext, RequestorEvent event) throws OAException
    {
        //DD SOAP HTTP server MUST return a "500 Internal Server Error" response and include a SOAP fault [saml-bindings-2.0-os r372]
        try 
        {
            /** XMLObjectBuilderFactory */
            XMLObjectBuilderFactory builderFactory = 
                Configuration.getBuilderFactory();            
            
            //Build SOAP Envelope and Body
            EnvelopeBuilder envBuilder = 
                (EnvelopeBuilder)builderFactory.getBuilder(
                    Envelope.DEFAULT_ELEMENT_NAME);
            Envelope envelope = envBuilder.buildObject();

            BodyBuilder bodyBuilder = (BodyBuilder)builderFactory.getBuilder(
                Body.DEFAULT_ELEMENT_NAME);   
            Body body = bodyBuilder.buildObject();
            
            //Build fault
            FaultCodeBuilder faultCodeBuilder = 
                (FaultCodeBuilder)builderFactory.getBuilder(
                FaultCode.DEFAULT_ELEMENT_NAME);
            FaultCode code = faultCodeBuilder.buildObject(
                FaultCode.DEFAULT_ELEMENT_NAME);
            FaultStringBuilder faultStringBuilder = 
                (FaultStringBuilder)builderFactory.getBuilder(
                FaultString.DEFAULT_ELEMENT_NAME);
            FaultString faultString = faultStringBuilder.buildObject(
                FaultString.DEFAULT_ELEMENT_NAME);
            switch(event)
            {               
                case REQUEST_INVALID:
                {
                    code.setValue(new QName(SOAPConstants.SOAP11_NS, "Client", 
                        SOAPConstants.SOAP11_PREFIX));
                    faultString.setValue(event.name());
                    break;
                }
                default:
                {
                    code.setValue(new QName(SOAPConstants.SOAP11_NS, "Server", 
                        SOAPConstants.SOAP11_PREFIX));
                    faultString.setValue(RequestorEvent.INTERNAL_ERROR.name());
                    break;
                }                
            }                        
            FaultBuilder faultBuilder = (FaultBuilder)builderFactory.getBuilder(
                Fault.DEFAULT_ELEMENT_NAME);
            Fault fault = faultBuilder.buildObject();              
            
            fault.setCode(code);
            
            fault.setMessage(faultString);
            
            body.getUnknownXMLObjects().add(fault);
            envelope.setBody(body);

            //Marshall message
            messageContext.setOutboundMessage(envelope);
            Marshaller m= Configuration.getMarshallerFactory().getMarshaller(
                Envelope.DEFAULT_ELEMENT_NAME);
            m.marshall(envelope);
            
            //Send SOAP Fault
            HTTPOutTransport outTransport = 
                (HTTPOutTransport)messageContext.getOutboundMessageTransport();
            HTTPTransportUtils.addNoCacheHeaders(outTransport);
            HTTPTransportUtils.setUTF8Encoding(outTransport);
            HTTPTransportUtils.setContentType(outTransport, "text/xml");
            outTransport.setHeader("SOAPAction", 
                "http://www.oasis-open.org/committees/security");

            outTransport.setStatusCode(
                HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            Writer out = new OutputStreamWriter(
                outTransport.getOutgoingStream(), SAML2Constants.CHARSET);
            XMLHelper.writeNode(envelope.getDOM(), out);
            out.flush();
        } 
        catch (UnsupportedEncodingException e) 
        {
            _logger.error(SAML2Constants.CHARSET + " encoding error" ,e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        } 
        catch (IOException e) 
        {
            _logger.error("I/O error while sending SOAP Fault", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (MarshallingException e)
        {
            _logger.error("Marshalling error while sending SOAP Fault", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }       
    }    
}
