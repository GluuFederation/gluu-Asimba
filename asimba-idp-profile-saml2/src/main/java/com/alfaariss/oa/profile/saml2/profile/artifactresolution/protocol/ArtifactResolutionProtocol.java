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
package com.alfaariss.oa.profile.saml2.profile.artifactresolution.protocol;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.ArtifactResponseBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.StatusException;
import com.alfaariss.oa.util.saml2.protocol.AbstractSAML2Protocol;
import com.alfaariss.oa.util.saml2.protocol.ISynchronousProtocol;

/**
 * Artifact Resolution Protocol implementation.
 *
 * The artifact resolution protocol provides a mechanism by which SAML protocol 
 * messages can be transported in a SAML binding by reference instead of by 
 * value.
 * 
 * This class implements the processing of the <code>ArtifactResolve</code> 
 * message and the construction of the <code>ArtifactResponse</code>.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class ArtifactResolutionProtocol extends AbstractSAML2Protocol 
    implements ISynchronousProtocol
{
    private SAMLArtifactMap _artifactMap;
    private static Log _logger;
      
    /**
     * Create a new <code>ArtifactResolutionProtocol</code>.
     * @param random The secure random generator.
     * @param artifactMap The artifact storage map to be used.
     * @param sProfileURL The profile URL.
     * @param issueInstantWindow The request issue instant window.
     */
    public ArtifactResolutionProtocol (SecureRandom random, 
        SAMLArtifactMap artifactMap, String sProfileURL, 
        SAML2IssueInstantWindow issueInstantWindow)
    {
        super(random, sProfileURL, issueInstantWindow);
        _logger = LogFactory.getLog(ArtifactResolutionProtocol.class);
        _artifactMap =  artifactMap;
    }
    
    /**
     * Process the Artifact Resolution Protocol request.
     * @see ISynchronousProtocol#processProtocol(org.opensaml.common.binding.SAMLMessageContext)
     */
    public void processProtocol(SAMLMessageContext<
        SignableSAMLObject, SignableSAMLObject, SAMLObject> 
        context) throws OAException, StatusException    
    {
        ArtifactResponse response = null;
        try
        { 
            //Create base response
            response = buildBaseArtifactResponse(context);
                       
            //retrieve request
            if(!(context.getInboundSAMLMessage() instanceof ArtifactResolve))
            {
                _logger.debug("Invalid request message: " 
                    + context.getInboundSAMLMessage());
                throw new StatusException(
                    RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI); 
            }
            ArtifactResolve request = (ArtifactResolve)context.getInboundSAMLMessage();
                                
            //Validate request and construct response
            
            Issuer issuer = request.getIssuer();
            if(issuer == null)
            {                
                //DD The <Issuer> element MUST be present and MUST contain the unique identifier of the requesting entity [saml-profiles-2.0-os r1488]
                _logger.debug("Missing issuer");
                throw new StatusException(
                    RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI); 
            }                  
            String sRequestorID = issuer.getValue();
            if(sRequestorID == null)
            {
                _logger.debug("Missing issuer value (requestor)");
                throw new StatusException(
                   RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI); 
            }
            
            String sFormat = issuer.getFormat();
            if(sFormat != null && !NameID.ENTITY.equals(sFormat))
            {
                //DD The Format attribute MUST be omitted or contain entity [saml-profiles-2.0-os r 1489]
                _logger.debug("Invalid issuer format: " + sFormat);
                throw new StatusException(sRequestorID, 
                    RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);
            }
                        
            String sRequestID = request.getID();
            if(sRequestID == null)
            {
                _logger.debug("Missing ID");
                throw new StatusException(sRequestorID, RequestorEvent.REQUEST_INVALID, 
                    StatusCode.REQUESTER_URI); 
            }
            response.setInResponseTo(sRequestID);
            
            SAMLVersion requestVersion = request.getVersion();            
            if(!SAMLVersion.VERSION_20.equals(requestVersion))
            {
                _logger.debug("Invalid request version: " + requestVersion);
                throw new StatusException(sRequestorID, 
                    RequestorEvent.REQUEST_INVALID, 
                    StatusCode.VERSION_MISMATCH_URI);
            }
            //Validate issue instant 
            DateTime issueInstant = request.getIssueInstant();
            if(issueInstant == null)
            {
                _logger.debug("Missing IssueInstant");
                throw new StatusException(sRequestorID, 
                    RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI); 
            }
            if(!_issueInstantWindow.canAccept(issueInstant))
            {
                _logger.debug("Invalid IssueInstant: " + issueInstant);
                throw new StatusException(sRequestorID, 
                    RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI); 
            }
            
            String sDestination = request.getDestination();
            if(sDestination != null)
            {               
                if(!sDestination.equalsIgnoreCase(_sProfileURL))
                {
                    _logger.debug("Invalid destination: " + sDestination);
                    throw new StatusException(sRequestorID, 
                        RequestorEvent.REQUEST_INVALID, 
                        StatusCode.REQUESTER_URI); 
                }
            }
     
            Artifact artifact = request.getArtifact();
            if(artifact == null)
            {
                _logger.debug("Missing Artifact");
                throw new StatusException( sRequestorID, 
                    RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI); 
            }
            
            //Retrieve entry
            SAMLArtifactMapEntry mapEntry = _artifactMap.get(artifact.getArtifact());
            //Validate entry 
            if(mapEntry == null)
            {
              //DD If the artifact is unknown, success status is returned without message [saml-core-2.0-os r2389]
                _logger.debug("Artifact unknown, possibly expired: " + artifact.getArtifact());
                throw new StatusException( sRequestorID, 
                    RequestorEvent.TOKEN_DEREFERENCE_FAILED, 
                    StatusCode.SUCCESS_URI); 
            }
                      
            if(mapEntry.isExpired())
            {
                //DD If the artifact is expired, success status is returned without message [saml-core-2.0-os r2389]
                _logger.debug("Artifact expired: " + mapEntry.getArtifact());
                throw new StatusException( sRequestorID, 
                    RequestorEvent.TOKEN_DEREFERENCE_FAILED, 
                    StatusCode.SUCCESS_URI); 
            }
     
            String relyingPartyId = mapEntry.getRelyingPartyId();
            if(relyingPartyId != null) //Issuer mandatory
            {
                //Validate SAML2 protocol                 
                if(!relyingPartyId.equals(sRequestorID))
                {
                    //DD If the artifact issuer is invalid, success status is returned without message [saml-core-2.0-os r2395]
                    _logger.debug("Invalid artifact relyingPartyId: " + relyingPartyId);
                    throw new StatusException( sRequestorID, 
                        RequestorEvent.REQUEST_INVALID, StatusCode.SUCCESS_URI); 
                }
            }

            //Construct valid response
            response.setMessage(mapEntry.getSamlMessage());
            response.setStatus(
                constructStatusCode(StatusCode.SUCCESS_URI, null));
           
            context.setOutboundSAMLMessage(response);
            
            //Remove artifact
            _artifactMap.remove(artifact.getArtifact());
        }
        catch(StatusException e) //Requestor error
        {              
            response.setStatus(constructStatusCode(e.getTopLevelstatusCode(), 
                e.getSecondLevelStatusCode()));
            context.setOutboundSAMLMessage(response);
            throw e;
        }       
        catch(Exception e) //fatal error
        {
            _logger.fatal("Internal processing error", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Create a <code>ArtifactResponse</code>.
     * @param context The message context.
     * @return A base ArtifactResponse containing ID, version and issueInstant.
     * @throws OAException If base64 encoding fails.
     */
    private ArtifactResponse buildBaseArtifactResponse( 
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
        context) throws OAException
    {
        //Create base response
        ArtifactResponseBuilder artifactResponseBuilder = 
            (ArtifactResponseBuilder)_builderFactory.getBuilder(
                ArtifactResponse.DEFAULT_ELEMENT_NAME);              
        ArtifactResponse response = artifactResponseBuilder.buildObject();
       
        try
        {
            super.populateResponse(response, null);
        }
        catch (UnsupportedEncodingException e)
        {
            _logger.error("Could not create response, unsupported encoding", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }        
        
        context.setOutboundSAMLMessageId(response.getID());             
        //Destination is omitted for synchronous bindings
        //Consent is omitted for ArtifactResponse
        
        //Build and set issuer
        IssuerBuilder issuerBuilder = (IssuerBuilder)_builderFactory.getBuilder(
            Issuer.DEFAULT_ELEMENT_NAME);
        
        Issuer responseIssuer = issuerBuilder.buildObject();
        responseIssuer.setFormat(NameID.ENTITY);
        responseIssuer.setValue(context.getLocalEntityId());   
        response.setIssuer(responseIssuer);
        
        return response;
    }

}
