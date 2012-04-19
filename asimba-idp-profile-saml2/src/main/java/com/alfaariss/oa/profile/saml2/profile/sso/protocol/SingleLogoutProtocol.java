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
package com.alfaariss.oa.profile.saml2.profile.sso.protocol;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.BaseID;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutResponseBuilder;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.TGTEventError;
import com.alfaariss.oa.api.tgt.TGTListenerException;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.util.saml2.NameIDFormatter;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.StatusException;
import com.alfaariss.oa.util.saml2.protocol.AbstractSAML2Protocol;
import com.alfaariss.oa.util.saml2.protocol.IASynchronousProtocol;

/**
 * Single Logout Protocol implementation.
 * 
 * The single logout protocol provides a message exchange protocol by which 
 * all sessions provided by the OA server are near-simultaneously terminated.
 *
 * This class implements the processing of the <code>LogoutRequest</code> 
 * message and the construction of the <code>logoutResponse</code>.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class SingleLogoutProtocol extends AbstractSAML2Protocol
    implements IASynchronousProtocol<ITGT>
{   
    private Log _logger;
    private NameIDFormatter _nameIDFormatter;
    private ITGTFactory _tgtfactory;
    private ITGTAliasStore _aliasStore;
    
    /**
     * Create a new <code>SingleLogoutProtocol</code>.
     * 
     * @param random The secure random generator.
     * @param profileURL The profile URL.
     * @param tgtfactory The TGT factory.
     * @param nameIDFormatter The name ID formatter to be used.
     * @param issueInstantWindow The request issue instant window.
     * @param tgtAliasStore TGT alias store.
     */
    public SingleLogoutProtocol (SecureRandom random, String profileURL, 
        ITGTFactory tgtfactory, NameIDFormatter nameIDFormatter,
        SAML2IssueInstantWindow issueInstantWindow, ITGTAliasStore tgtAliasStore)
    {
        super(random, profileURL, issueInstantWindow);
        _logger = LogFactory.getLog(SingleLogoutProtocol.class);
        _tgtfactory = tgtfactory; 
        _nameIDFormatter = nameIDFormatter;
        _aliasStore = tgtAliasStore;
    }

    /**
     * Processes a <code>&lt;LogoutRequest&gt;</code>.
     * @see IASynchronousProtocol#processRequest(
     *  org.opensaml.common.binding.SAMLMessageContext)
     */
    public ITGT processRequest(
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> context)
        throws OAException, StatusException
    {
        ITGT tgt = null;
        String sRequestID = null;
        try
        { 
            //retrieve request
            if(!(context.getInboundSAMLMessage() instanceof LogoutRequest))
            {
                _logger.debug("Invalid request message: " 
                    + context.getInboundSAMLMessage());
                throw new StatusException(
                    RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI); 
            }
            LogoutRequest request = (LogoutRequest)context.getInboundSAMLMessage();
            
            //Validate request TODO EVB: move basic validation to super class
            Issuer issuer = request.getIssuer();
            if(issuer == null)
            {                
                //The <Issuer> element MUST be present and MUST contain the 
                //unique identifier of the requesting entity [saml-profiles-2.0-os r1294]
                //OA MUST authenticate the sender [saml-core-2.0-os r2590, r2618]
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
                //DD The Format attribute MUST be omitted or contain entity [saml-profiles-2.0-os r1295]
                _logger.debug("Invalid issuer format: " + sFormat);
                throw new StatusException(sRequestorID, 
                    RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);
            }
                    
            sRequestID = request.getID();
            if (sRequestID == null)
            {
                _logger.debug("Missing request ID");
                throw new StatusException(sRequestorID,
                   RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI); 
            }      
            
            SAMLVersion samlVersion = request.getVersion();
            if (samlVersion == null || !samlVersion.equals(SAMLVersion.VERSION_20))
            {
                _logger.debug("Unsupported SAML version in request: " + samlVersion);
                throw new StatusException(sRequestorID, 
                    RequestorEvent.REQUEST_INVALID, 
                    StatusCode.VERSION_MISMATCH_URI);
            }
            
            DateTime issueInstant = request.getIssueInstant();
            if (issueInstant == null)
            {
                _logger.debug("No IssueInstant in request");
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
            if (sDestination != null)
            {   if (!sDestination.equalsIgnoreCase(_sProfileURL))
                {
                    _logger.debug(
                        "Invalid Destination in request: " + sDestination);
                    throw new StatusException(sRequestorID, 
                        RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);
                }
            }
            
            String consent = request.getConsent();
            if (consent != null)
            {
                //DD Consent will be ignored
                _logger.debug("Consent in request: " + consent);
            }
            
            //Validate NotOnOrAfter
            DateTime notOnOrAfter = request.getNotOnOrAfter();
            if(notOnOrAfter != null)
            {
                if(notOnOrAfter.isBeforeNow())
                {
                    _logger.debug(
                        "Request expired: " + notOnOrAfter);
                    throw new StatusException(sRequestorID, 
                        RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);              
                }
            }
            String sNameAlias = null;
            String sNameFormat = null;
            EncryptedID encID = request.getEncryptedID();
            if(encID  != null)
            {
                //TODO EVB: support for EncryptedID
                _logger.debug("EncryptedID in request");
            }
            BaseID baseID = request.getBaseID();
            if(baseID  != null)
            {
                _logger.debug("BaseID in request: " + baseID.getElementQName());
            }
            NameID nameID = request.getNameID();
            if(nameID != null)
            {
                if(nameID.getValue() == null)
                {
                    _logger.debug(
                        "Invalid NameID in request: " + nameID);
                    throw new StatusException(sRequestorID, 
                        RequestorEvent.REQUEST_INVALID, 
                        StatusCode.REQUESTER_URI);
                }
                
                sNameFormat = nameID.getFormat();
                if(sNameFormat == null)
                    sNameFormat = NameIDType.UNSPECIFIED;
                if(!_nameIDFormatter.isSupported(sNameFormat))
                {
                    _logger.debug(
                        "NameFormat not supported: " + nameID.getFormat());
                    throw new StatusException(sRequestorID, 
                        RequestorEvent.REQUEST_INVALID, 
                        StatusCode.REQUESTER_URI);
                }
                sNameAlias = nameID.getValue();      
            }
            
            if(sNameAlias == null)
            {
                _logger.debug(
                    "No name alias could be extracted from request");
                throw new StatusException(sRequestorID, 
                    RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);              
            }
                        
            List<SessionIndex> sessionIndexes = request.getSessionIndexes();
            //At least one SessionIndex element MUST be included (saml-profiles-2.0-os 1207)
            if(sessionIndexes.size() == 0)
            {
                _logger.debug(
                "No sessionindex found in request");
                throw new StatusException(sRequestorID, 
                    RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);
            }
            //TODO handle multiple session indexes correctly
            //Get tgt ID with from alias storage.
            
            String sSessionIndex = null;
            for(SessionIndex sessionIndex : sessionIndexes)
            {
                sSessionIndex = sessionIndex.getSessionIndex();
                if(sSessionIndex == null)
                {
                    _logger.debug("Empty sessionindex found in request");
                    throw new StatusException(sRequestorID, 
                        RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);
                }
                
                String sTGT = _aliasStore.getTGTID(
                    NameIDFormatter.TYPE_ALIAS_TGT, sRequestorID, 
                    sSessionIndex);
                if(sTGT == null)
                {
                    _logger.debug(
                        "No corresponding TGT found for session index: " 
                        + sSessionIndex);                    
                }
                else
                {
                    //Retrieve TGT
                    tgt = _tgtfactory.retrieve(sTGT);
                    if(tgt == null)
                    {
                        _logger.debug(
                            "TGT not found for session index: " + sessionIndex);
                        throw new StatusException(sRequestorID, 
                        RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);
                    }    
                    break;
                }
            }
            
            if(tgt == null)
            {
                _logger.debug(
                    "No TGT found for session indexes: " + sessionIndexes);
                throw new StatusException(sRequestorID, 
                RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);
            }                 
            
            //DD TGT expired -> ignore for logout            
            if(!tgt.isExpired())
            {
                //The name ID should strongly match: verify TGT user and nameID
                if( !_nameIDFormatter.verify(
                    sNameFormat, sNameAlias, sRequestorID, tgt.getId()))
                {
                    StringBuffer sbError = new StringBuffer("Invalid alias value '");
                    sbError.append(sNameAlias);                    
                    sbError.append("' for NameFormat '");
                    sbError.append(sNameFormat);
                    sbError.append("',  requestor '");
                    sbError.append(sRequestorID);
                    sbError.append("' and TGT with ID: ");
                    sbError.append(tgt.getId());
                    _logger.debug(sbError.toString());
                    throw new StatusException(sRequestorID, 
                        RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);
                }
                
                //DD remove the session index alias, so offline logout won't be triggered back to this requestor
                if (_aliasStore.isAlias(NameIDFormatter.TYPE_ALIAS_TGT, 
                    sRequestorID, sSessionIndex))
                {
                    _aliasStore.removeAlias(NameIDFormatter.TYPE_ALIAS_TGT, 
                        sRequestorID, sSessionIndex);
                }
            }
                        
            return tgt;
        }
        catch(StatusException e) //Requestor error
        {              
            LogoutResponse response = createResponse(context);
            response.setStatus(constructStatusCode(e.getTopLevelstatusCode(), 
                e.getSecondLevelStatusCode()));
            if(sRequestID != null)
                response.setInResponseTo(sRequestID);
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
     * Perform the <code>&lt;LogoutResponse&gt;</code>.
     * 
     * Expire the TGT and construct a response.
     * 
     * @param tgt The resolved TGT. If NULL, the logout result will be success.
     * @param inResponseTo The original message ID.
     * @param context The mnessage context.
     * @throws OAException If processing fails due to internal error.
     * @see IASynchronousProtocol#processResponse(java.lang.Object, 
     *  java.lang.String, org.opensaml.common.binding.SAMLMessageContext)
     */
    public void processResponse(ITGT tgt, String inResponseTo,
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> context)
        throws OAException
    {
        processResponse(tgt, inResponseTo, context, false);
    }
    
    /**
     * Perform the <code>&lt;LogoutResponse&gt;</code>.
     * 
     * Expire the TGT and construct a response.
     * 
     * @param tgt The resolved TGT. If NULL, the logout result will be success.
     * @param inResponseTo The original message ID.
     * @param context The mnessage context.
     * @param bIsPartiallyLogout Is partially logging out.
     * @throws OAException If processing fails due to internal error.
     * @see IASynchronousProtocol#processResponse(java.lang.Object, 
     *  java.lang.String, org.opensaml.common.binding.SAMLMessageContext)
     */
    public void processResponse(ITGT tgt, String inResponseTo,
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> context,
        boolean bIsPartiallyLogout)
        throws OAException
    {
        try
        {
            LogoutResponse response = createResponse(context);
            response.setInResponseTo(inResponseTo);
            
            Status status = null; 
            String sSecondLevelStatusCode = null;
            try
            {
                //DD If a TGT is supplied, the request was sent with a synchronous binding, meaning the TGT must be persisted
                if (tgt != null)
                {
                    if (bIsPartiallyLogout)
                    {//only logout the requestor
                        sSecondLevelStatusCode = StatusCode.PARTIAL_LOGOUT_URI;
                    }
                    else
                    {//logout everything
                        if(!tgt.isExpired())
                            tgt.expire();
                    }
                    
                    tgt.persist();
                }
                
                //DD If no TGT was supplied, the request was sent with an a-synchronous binding, meaning the TGT was already removed at /openaselect/sso/logout
                status = constructStatusCode(StatusCode.SUCCESS_URI, sSecondLevelStatusCode);
            }
            catch (TGTListenerException e)
            {
                status = getLogoutStatus(e.getErrors());
            }
            
            response.setStatus(status);
            
            context.setOutboundSAMLMessage(response);
        }
        catch(PersistenceException e)
        {
            _logger.error("Could not expire TGT", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
  
    /**
     * Create a SAML error response.
     * 
     * If the OA Server refuses to perform a message exchange with the 
     * SAML requester a SAML response message must be sent.
     * 
     * The error response is set in the message context.
     * 
     * @param context The message context.
     * @param topLevelstatusCode The top-level status code.
     * @param secondLevelStatusCode The second-level status code.
     * @param inResponseTo The Request ID.
     * @throws OAException If building fails due to internal error.
     */
    public void buildErrorResponse(
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> context, 
        String topLevelstatusCode, String secondLevelStatusCode, String inResponseTo)
        throws OAException
    {       
        LogoutResponse response = createResponse(context);
        response.setStatus(constructStatusCode(
            topLevelstatusCode, secondLevelStatusCode));
       
        if(inResponseTo != null)
            response.setInResponseTo(inResponseTo);
        
        context.setOutboundSAMLMessage(response);   
    }
    
    private LogoutResponse createResponse(
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> context)
        throws OAException
    {
        //Create base response
        LogoutResponseBuilder logoutResponseBuilder = 
            (LogoutResponseBuilder)_builderFactory.getBuilder(
                LogoutResponse.DEFAULT_ELEMENT_NAME);              
        LogoutResponse response = logoutResponseBuilder.buildObject();
        try
        {
            super.populateResponse(response, null);
        }
        catch (UnsupportedEncodingException e)
        {
            _logger.error("Could not create response, unsupported encoding", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }    
        
        
        //Build and set issuer
        IssuerBuilder issuerBuilder = (IssuerBuilder)_builderFactory.getBuilder(
            Issuer.DEFAULT_ELEMENT_NAME);
        
        Issuer responseIssuer = issuerBuilder.buildObject();
        responseIssuer.setFormat(NameID.ENTITY);
        responseIssuer.setValue(context.getLocalEntityId());   
        response.setIssuer(responseIssuer);
        
        context.setOutboundSAMLMessageId(response.getID());      
      
        return response;
    }
 
    private Status getLogoutStatus(List<TGTEventError> listErrors)
    {
        Status status = constructStatusCode(StatusCode.RESPONDER_URI, null);
        
        for (TGTEventError eventError: listErrors)
        {
            switch(eventError.getCode())
            {
                case USER_LOGOUT_PARTIALLY:
                {
                    status = constructStatusCode(StatusCode.SUCCESS_URI,
                        StatusCode.PARTIAL_LOGOUT_URI);
                    break;
                }
                case USER_LOGOUT_IN_PROGRESS:
                case USER_LOGOUT_FAILED:
                default:
                {
                    //do not search further; logout failed already.
                    return constructStatusCode(StatusCode.RESPONDER_URI, null);
                }
            }
        }
        
        return status;
    }
}
