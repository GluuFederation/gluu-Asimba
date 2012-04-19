/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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

import java.security.NoSuchAlgorithmException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004Builder;
import org.opensaml.saml2.binding.decoding.HTTPArtifactDecoder;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.impl.ArtifactBuilder;
import org.opensaml.saml2.core.impl.ArtifactResolveBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.impl.BodyBuilder;
import org.opensaml.ws.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import com.alfaariss.oa.util.saml2.binding.BindingProperties;

/**
 * OA implemented artifact decoder. Partially replaces the OpenSAML 
 * HTTPArtifactDecoder. This version may need to be made more independent, 
 * since some of the data necessary to retrieve the artifacts are now put in the
 * context beforehand.
 * 
 *  This artifact decoder supports 
 *  
 * @see org.opensaml.saml2.binding.decoding.HTTPArtifactDecoder
 * @author jre
 * @author Alfa & Ariss
 * @since 1.0
 */
public class ImplementedHTTPArtifactDecoder extends HTTPArtifactDecoder
{
    //DD Signature in message within ArtifactResponse types is currently not verified, because there currently is no opportunity to do so.
    
    private final Log _logger = LogFactory.getLog(ImplementedHTTPArtifactDecoder.class);
    private XMLObjectBuilderFactory _builderFactory;   
    private String _sSSODescriptor;
    
    /**
     * Default constructor.
     *  
     * @param pool Basic parser pool.
     * @param bindingProperties The binding properties configuration.
     */
    public ImplementedHTTPArtifactDecoder(ParserPool pool, BindingProperties bindingProperties) 
    {
        super(pool);
        _builderFactory = Configuration.getBuilderFactory();
        _sSSODescriptor = bindingProperties.getProperty(
            SAMLConstants.SAML2_ARTIFACT_BINDING_URI, "SSODescriptor");
    }

    /**
     * @see org.opensaml.saml2.binding.decoding.HTTPArtifactDecoder#processArtifact(org.opensaml.common.binding.SAMLMessageContext)
     */
    @SuppressWarnings("unchecked")
    protected void processArtifact(SAMLMessageContext samlMsgCtx) throws MessageDecodingException 
    {        
        HTTPInTransport inTransport = (HTTPInTransport) samlMsgCtx.getInboundMessageTransport();
        String encodedArtifact = DatatypeHelper.safeTrimOrNullString(inTransport.getParameterValue("SAMLart"));
        if (encodedArtifact == null) 
        {
            _logger.error("URL SAMLart parameter was missing or did not contain a value");
            throw new MessageDecodingException("URL TARGET parameter was missing or did not contain a value");
        }
        
        ArtifactBuilder artifactBuilder = (ArtifactBuilder) _builderFactory
            .getBuilder(Artifact.DEFAULT_ELEMENT_NAME);
        Artifact artifact = artifactBuilder.buildObject();
        artifact.setArtifact(encodedArtifact);

        ArtifactResolveBuilder artifactResolveBuilder = (ArtifactResolveBuilder)
            _builderFactory.getBuilder(ArtifactResolve.DEFAULT_ELEMENT_NAME);
        ArtifactResolve artifactResolve = artifactResolveBuilder.buildObject();
        
        SecureRandomIdentifierGenerator idgen = null;
        try
        {
            idgen = new SecureRandomIdentifierGenerator();
        }
        catch (NoSuchAlgorithmException e)
        {
            String msg = "Could not generate ID for artifact resolve request";
            _logger.debug(msg);
            throw new MessageDecodingException(msg, e);
        }
        
        String id = idgen.generateIdentifier();
        
        artifactResolve.setID(id);
        artifactResolve.setVersion(SAMLVersion.VERSION_20);
        artifactResolve.setIssueInstant(new DateTime());
        artifactResolve.setArtifact(artifact);
        
        IssuerBuilder issuerBuilder = (IssuerBuilder) _builderFactory
            .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(samlMsgCtx.getOutboundMessageIssuer());
        
        artifactResolve.setIssuer(issuer);
        
        MetadataProvider mp = samlMsgCtx.getMetadataProvider();
        if (mp == null) 
        {
            _logger.debug("No MetadataProvider available in message context");
            throw new MessageDecodingException("No MetadataProvider available in message context");
        }
        
        String entID = samlMsgCtx.getInboundMessageIssuer();
        String endpoint = null;
        
        try
        {
            SSODescriptor rd = null;
            if (_sSSODescriptor != null)
            {
                if ("sp".equalsIgnoreCase(_sSSODescriptor))
                {
                    rd = (SPSSODescriptor)mp.getRole(entID, 
                        SPSSODescriptor.DEFAULT_ELEMENT_NAME, 
                        SAMLConstants.SAML20P_NS);
                }
                else if ("idp".equalsIgnoreCase(_sSSODescriptor))
                {
                    rd = (IDPSSODescriptor)mp.getRole(entID, 
                        IDPSSODescriptor.DEFAULT_ELEMENT_NAME, 
                        SAMLConstants.SAML20P_NS);
                }
                else
                {
                    StringBuffer sbDebug = new StringBuffer("Unknown SSODescriptor configured '");
                    sbDebug.append(_sSSODescriptor);
                    sbDebug.append("'; using IDPSSODescriptor");
                    _logger.debug(sbDebug.toString());
                }
            }
            
            if (rd == null)
            {//default use IDP role
                rd = (IDPSSODescriptor)mp.getRole(entID, 
                    IDPSSODescriptor.DEFAULT_ELEMENT_NAME, 
                    SAMLConstants.SAML20P_NS);
            }
            
            if (rd != null)
            {
                SAML2ArtifactType0004 b = null;
                SAML2ArtifactType0004Builder bf = new SAML2ArtifactType0004Builder();
                b = bf.buildArtifact(Base64.decode(encodedArtifact));
                
                String defaultEndpoint = null;
                String indexedEndpoint = null;
                String firstEndpoint = null;
                
                for(ArtifactResolutionService ars : rd.getArtifactResolutionServices())
                {
                    if (firstEndpoint == null) firstEndpoint = ars.getLocation();
                    if (ars.isDefault()) defaultEndpoint = ars.getLocation();
                    
                    int i = 0;
                    byte[] ba = b.getEndpointIndex();
                    
                    for (int ia = ba.length-1 ; ia >= 0; ia--)
                    {
                        i = i + (ba[ia] * Byte.SIZE);
                    }
                    
                    if (ars.getIndex() == i)
                    {
                        indexedEndpoint = ars.getLocation();
                    }
                }
                
                //choose right endpoint:
                if (indexedEndpoint != null) endpoint = indexedEndpoint;
                else if (defaultEndpoint != null) endpoint = defaultEndpoint;
                else endpoint = firstEndpoint;
            }
        }
        catch (MetadataProviderException e1)
        {
            String msg = "Exception while fetching metadata for requestor while decoding artifact";
            _logger.debug(msg);
            throw new MessageDecodingException(msg, e1);
        }
        
        if (endpoint == null)
        {
            String msg = "Could not fetch endpoint for requestor while decoding artifact";
            _logger.debug(msg);
            throw new MessageDecodingException(msg);
        }

        BodyBuilder bodyBuilder = (BodyBuilder) _builderFactory
            .getBuilder(Body.DEFAULT_ELEMENT_NAME);
        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(artifactResolve);
        
        EnvelopeBuilder envelopeBuilder = (EnvelopeBuilder) _builderFactory
            .getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
        Envelope env = envelopeBuilder.buildObject();
        env.setBody(body);

        BasicSOAPMessageContext soapContext = new BasicSOAPMessageContext();
        soapContext.setOutboundMessage(env);
        
        HttpClientBuilder clientBuilder = new HttpClientBuilder();
        clientBuilder.setConnectionTimeout(5000);

        HttpSOAPClient soapClient = new HttpSOAPClient(
            clientBuilder.buildClient(), super.getParserPool());

        if (_logger.isDebugEnabled())
            logXML(env);
        
        try
        {
            soapClient.send(endpoint, soapContext);
        }
        catch (Exception e)
        {
            String msg = "Could not resolve artifact";
            _logger.debug(msg, e);
            throw new MessageDecodingException(msg, e);
        }
        
        Envelope envelope = (Envelope)soapContext.getInboundMessage();
        
        if (_logger.isDebugEnabled())
            logXML(envelope);
        
        XMLObject samlResponseMessage = null;
        XMLObject responseMessage = soapContext.getInboundMessage();
        if (responseMessage != null && responseMessage instanceof Envelope)
        {
            Envelope responseEnvelope = (Envelope)responseMessage;
            Body responseBody = responseEnvelope.getBody();
            if (responseBody != null)
            {
                samlResponseMessage = responseBody.getUnknownXMLObjects().get(0);
            }
            else
            {
                _logger.debug("No body in response message");
            }
        }
        else
        {
            _logger.debug("No envelope in response message");
        }
        
        if (samlResponseMessage != null && samlResponseMessage instanceof ArtifactResponse)
        {
            ArtifactResponse artResp = (ArtifactResponse)samlResponseMessage;
            SAMLObject message = artResp.getMessage();
            if (message instanceof StatusResponseType)
                samlMsgCtx.setInboundSAMLMessage(message);
        }
        else
        {
            _logger.debug("Response doesn't contain an ArtifactResponse object");
        }
    }
    
    /**
     * Log XML to logger.
     * 
     * @param xmlObject the Object to be logged.
     */
    protected void logXML(XMLObject xmlObject)
    {
        assert _logger.isDebugEnabled() : "Logger debug state not checked";
        Element eDOM = xmlObject.getDOM();
        if(eDOM == null)
        {
            Marshaller marshaller = 
                Configuration.getMarshallerFactory().getMarshaller(xmlObject);
            if (marshaller != null) 
            {
                try
                {
                    eDOM = marshaller.marshall(xmlObject);
                }
                catch (MarshallingException e)
                {
                    _logger.debug("Could not prettyPrint XML object", e);
                }
            }
        }
            
        if (eDOM != null)
        {
            String sXML = XMLHelper.prettyPrintXML(eDOM);
            _logger.debug(sXML);
        }
        
    }

}
