/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
package com.alfaariss.oa.profile.saml2.profile.artifactresolution;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.profile.saml2.profile.artifactresolution.protocol.ArtifactResolutionProtocol;
import com.alfaariss.oa.util.logging.RequestorEventLogItem;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.ISAML2Requestors;
import com.alfaariss.oa.util.saml2.SAML2SecurityException;
import com.alfaariss.oa.util.saml2.StatusException;
import com.alfaariss.oa.util.saml2.binding.AbstractDecodingFactory;
import com.alfaariss.oa.util.saml2.binding.AbstractEncodingFactory;
import com.alfaariss.oa.util.saml2.binding.soap11.SOAP11Utils;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;
import com.alfaariss.oa.util.saml2.metadata.role.sso.IDPSSODescriptorBuilder;
import com.alfaariss.oa.util.saml2.profile.AbstractSAML2Profile;
import com.alfaariss.oa.util.saml2.profile.ISAML2Profile;
import com.alfaariss.oa.util.saml2.storage.artifact.ArtifactStoreFactory;

/**
 * Artifact Resolution Profile implementation.
 *
 * Implements the Artifact Resolution protocol for dereferencing a SAML 
 * artifact into a corresponding protocol message.
 * 
 * @author EVB
 * @author Alfa & Ariss
 * @see <a 
 *  href="http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf" 
 *  target="_new">
 *  Profiles for the OASIS Security Assertion Markup Language (SAML) V2.0
 *  </a>
 */
public class ArtifactResolutionService extends AbstractSAML2Profile
{   
    /** XMLObjectBuilderFactory */
    protected XMLObjectBuilderFactory _builderFactory;
    
    private static Log _logger = LogFactory.getLog(
        ArtifactResolutionService.class);
    private Log _eventLogger;
    /** The protocol handler */
    private ArtifactResolutionProtocol _protocol;
       
    /**
     * Constructor. 
     */
    public ArtifactResolutionService ()
    {
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER); 
        _builderFactory = Configuration.getBuilderFactory();
    }

    /**
     * @see AbstractSAML2Profile#init(IConfigurationManager, Element, 
     * EntityDescriptor, String, String, SAML2Requestors, 
     * SAML2IssueInstantWindow, String)
     */
    public void init(IConfigurationManager configurationManager,
        Element config, EntityDescriptor entityDescriptor, 
        String sBaseUrl, String sWebSSOPath, ISAML2Requestors requestors, 
        SAML2IssueInstantWindow issueInstantWindow, String sProfileID) 
        throws OAException
    {
        super.init(configurationManager, config, entityDescriptor, sBaseUrl, 
            sWebSSOPath, requestors, issueInstantWindow, sProfileID);
        
        //Start Artifact storage 
        ArtifactStoreFactory factory = ArtifactStoreFactory.getInstance();
        factory.init(configurationManager, config, _cryptoManager);
        SAMLArtifactMap artifactStorage = factory.getStoreInstance();
        
        //Create protocol
        _protocol = new ArtifactResolutionProtocol(
            _cryptoManager.getSecureRandom(),
            artifactStorage, _sProfileURL, _issueInstantWindow);
        
        //Append role descriptor
        IDPSSODescriptor idpSSODescriptor = 
            entityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
       
        IDPSSODescriptorBuilder builder = new IDPSSODescriptorBuilder(
            configurationManager, config, idpSSODescriptor);
               
        //Build ArtifactResolutionService
        builder.buildArtifactResolutionService(_sProfileURL);
        
        _logger.info("ArtifactResolutionService Started at endpoint: " 
            + _sProfileURL);
    }

    /**
     * @see ISAML2Profile#process(javax.servlet.http.HttpServletRequest, 
     *  javax.servlet.http.HttpServletResponse)
     */
    public void process(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) throws OAException
    {
        SAMLMessageContext<SignableSAMLObject, 
            SignableSAMLObject,SAMLObject>  context = null;
        try
        {
            //Decode SOAP message
            AbstractDecodingFactory decFactory = 
                AbstractDecodingFactory.createInstance(
                    servletRequest, servletResponse, 
                    SAMLConstants.SAML2_SOAP11_BINDING_URI, null);

            SAMLMessageDecoder decoder = decFactory.getDecoder();                       
            context = decFactory.getContext();
            context.setLocalEntityId(_sEntityID);
            context.setLocalEntityMetadata(_entityDescriptor);
            
            //Decode request
            try
            {
                decoder.decode(context);
            }
            catch (SecurityException e)
            {
                _logger.debug(
                    "Could not decode inbound message due to security exception", e);
               throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
            }
            
            //verify saml message in request
            SignableSAMLObject requestMessage = context.getInboundSAMLMessage();
            
            if (_logger.isDebugEnabled())
            {
                if (requestMessage != null)
                    logXML(requestMessage);
            }
            
            //Validate requestor and signature
            validateRequest(context,SPSSODescriptor.DEFAULT_ELEMENT_NAME);
             
            _protocol.processProtocol(context);
            //DD TOKEN_DEREFERENCE events are used for artifact resolution
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                RequestorEvent.TOKEN_DEREFERENCE_SUCCESSFUL, null,
                servletRequest.getRemoteAddr(), 
                context.getInboundMessageIssuer(), this, 
                context.getOutboundSAMLMessageId()));
            
            sendResponse(context, servletRequest, servletResponse);           
        }
        catch(StatusException e) //SAML processing error
        {
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                e.getEvent(), null, servletRequest.getRemoteAddr(), 
                e.getRequestorID(), this, e.getMessage()));
            
            sendResponse(context, servletRequest, servletResponse);
        }
        catch (MessageDecodingException e) //SOAP binding processing error  
        {    
           _logger.debug(
               "SOAP decoding error", e);
           _eventLogger.info(new RequestorEventLogItem(null, null, null, 
               RequestorEvent.REQUEST_INVALID, null, 
               servletRequest.getRemoteAddr(), null, this, "SOAP Fault"));
           SOAP11Utils.sendSOAPFault(context, RequestorEvent.REQUEST_INVALID);
        }
        catch (SAML2SecurityException e)
            //The message does not meet the required security constraints
        {            
            //DD Security error -> Return a "403 Forbidden" response [saml-bindings-2.0-os r370]
            _logger.debug(
                "Security error", e);
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                e.getEvent(), null, servletRequest.getRemoteAddr(), 
                null, this, "Security Fault"));
            try
            {
                if (!servletResponse.isCommitted())
                    servletResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
            catch (IOException e1)
            {
                _logger.warn("Could not send response", e1);
            }
        }
        catch (OAException e) //Internal error
        {
            throw e;
        }         
        catch (Exception e)
        {
            _logger.fatal("Could not process SAML request message", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }        
    }  

    /**
     * Close artifact storage service.
     * @see ISAML2Profile#destroy()
     */
    public void destroy()
    {        
        //Stop Artifact storage
        ArtifactStoreFactory.getInstance().stop();
        super.destroy();
    }

    //Send SAML response message using SOAP binding
    private void sendResponse(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject,SAMLObject> context, 
        HttpServletRequest servletRequest,  
        HttpServletResponse servletResponse) throws OAException
    {
        try
        {            
            //Prepare the response signing
            if (_signingEnabled)
            {
                Credential credentials = SAML2CryptoUtils.retrieveMySigningCredentials(
                    _cryptoManager, _sEntityID);  
                context.setOutboundSAMLMessageSigningCredential(credentials);
            }
            
            AbstractEncodingFactory encodingFactory = 
                AbstractEncodingFactory.createInstance(servletRequest, 
                    servletResponse, SAMLConstants.SAML2_SOAP11_BINDING_URI, 
                    null);       
            SAMLMessageEncoder encoder = encodingFactory.getEncoder();      
            encoder.encode(context);
            
            if (_logger.isDebugEnabled())
            {
                XMLObject xmlObject = context.getOutboundSAMLMessage();
                if (xmlObject != null)
                    logXML(xmlObject);
            }
        }
        catch (MessageEncodingException e)
        {
            _logger.error("Could not send reponse with binding " 
                + SAMLConstants.SAML2_SOAP11_BINDING_URI, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
}
