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
package com.alfaariss.oa.profile.saml2.profile.sso.protocol;

import java.security.SecureRandom;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.StatusException;
import com.alfaariss.oa.util.saml2.protocol.AbstractSAML2Protocol;
import com.alfaariss.oa.util.saml2.proxy.ProxyAttributes;


/**
 * Abstract SAML2 Protocol implementation.
 *
 * @author MHO
 * @author Alfa & Ariss
 */
public abstract class AbstractAuthenticationRequestProtocol 
    extends AbstractSAML2Protocol
{
    /** ID */
    public final static String SESSION_REQUEST_ID = "ID";
    
    /** User authentication session */
    protected ISession _session;
    /** The ID in the request message */
    protected String _sRequestID;
    /** The IDP Entitiy ID */
    protected String _sEntityID;
    /** Sets whether the shadowed Idp Entity gets to be used */
    protected boolean _bEnableShadowIdp;
    /** The EntityId that we pretend to be for the Requester (optional);
     * if it contains a non-null value, the feature is enabled implicitly  */
    protected String _sShadowedEntityId = null;
    
    private Log _logger;
    
    /**
     * Creates the object. 
     * @param random Random generator
     * @param sProfileURL The profile URL
     * @param session The user session
     * @param sEntityId The Entitiy ID
     * @param issueInstantWindow IssueInstant time window object
     */
    public AbstractAuthenticationRequestProtocol(SecureRandom random, 
        String sProfileURL, ISession session, String sEntityId, 
        SAML2IssueInstantWindow issueInstantWindow, boolean bEnableShadowedIdp)
    {
        super(random, sProfileURL, issueInstantWindow);
        _logger = LogFactory.getLog(AbstractAuthenticationRequestProtocol.class);
        _session = session;
        _sEntityID = sEntityId;
        _bEnableShadowIdp = bEnableShadowedIdp;
        
        readSessionAttributes(_session);
    }

    /**
     * Creates a StatusResponse object with supplied statuscodes.
     * @param sDestination  The response destination URL.
     * @param sTopLevelStatusCode Top-Level StatusCode
     * @param sSecondLevelStatusCode Second-Level StatusCode 
     * @return A status response.
     * @throws OAException If error response could not be created.
     */
    public StatusResponseType createErrorResponse(String sDestination, 
        String sTopLevelStatusCode, String sSecondLevelStatusCode) 
        throws OAException
    {
        ResponseBuilder builder = (ResponseBuilder)_builderFactory.getBuilder(
            Response.DEFAULT_ELEMENT_NAME);
        
        StatusResponseType response = builder.buildObject();
        response = createResponse(sDestination, response, sTopLevelStatusCode, 
            sSecondLevelStatusCode);
        return response;
    }

    /**
     * Processes the default request properties.
     *
     * @param request The request to process.
     * @throws OAException If processing fails.
     * @throws StatusException If an error response should be sent.
     */
    protected void processRequestAbstractType(RequestAbstractType request) 
        throws OAException, StatusException
    {
        try
        {
            ISessionAttributes oAttributes = _session.getAttributes();
            
            _sRequestID = request.getID();
            if (_sRequestID != null)
                oAttributes.put(AbstractAuthenticationRequestProtocol.class, SESSION_REQUEST_ID
                    , _sRequestID);
            
            SAMLVersion samlVersion = request.getVersion();
            if (!samlVersion.equals(SAMLVersion.VERSION_20))
            {
                _logger.debug("Unsupported SAML version in request: " + samlVersion);
                throw new StatusException(RequestorEvent.REQUEST_INVALID, StatusCode.VERSION_MISMATCH_URI);
            }
            
            DateTime dateTime = request.getIssueInstant();
            if (dateTime == null)
            {
                _logger.debug("No IssueInstant in request");
                throw new StatusException(RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);
            }
            
            if(!_issueInstantWindow.canAccept(dateTime))
            {
                _logger.debug("Invalid IssueInstant in request: " + dateTime);
                throw new StatusException(RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);
            }
            
            String sDestination = request.getDestination();
            if (sDestination != null)
            {   if (!sDestination.equalsIgnoreCase(_sProfileURL))
                {
                    _logger.debug("Invalid Destination in request: " + sDestination);
                    throw new StatusException(RequestorEvent.REQUEST_INVALID, StatusCode.REQUESTER_URI);
                }
            }
            
            String consent = request.getConsent();
            if (consent != null)
            {
                //DD Consent will be ignored
                _logger.debug("Consent in request: " + consent);
            }
            
            Issuer issuer = request.getIssuer();
            if (issuer == null)
            {
                _logger.debug("No Issuer in request");
                throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                    StatusCode.REQUESTER_URI);
            }
            
            String issuerFormat = issuer.getFormat();
            if (issuerFormat != null && !issuerFormat.equals(Issuer.ENTITY))
            {
                _logger.debug("Invalid Issuer format in request: " + issuerFormat);
                throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                    StatusCode.REQUESTER_URI);
            }
        }
        catch (StatusException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during request processing", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Create a default response object with only a top-level status code.
     * @param sDestination The response destination URL.
     * @param response The SAML response.
     * @param sTopLevelStatusCode The top-level status code.
     * @return StatusResponseType The created response object.
     * @throws OAException If creation fails.
     */
    protected StatusResponseType createResponse(String sDestination, StatusResponseType response,
        String sTopLevelStatusCode) throws OAException
    {
        return createResponse(sDestination, response, sTopLevelStatusCode, null);
    }
    
    /**
     * Create a default response object.
     * @param sDestination The response destination URL.
     * @param response The SAML response.
     * @param sTopLevelStatusCode The top-level status code.
     * @param sSecondLevelStatusCode The second-level status code. 
     * @return The updated response.
     * @throws OAException If creation fails.
     */
    protected StatusResponseType createResponse(String sDestination, StatusResponseType response,
        String sTopLevelStatusCode, String sSecondLevelStatusCode) 
        throws OAException
    {
        try
        {
            populateResponse(response, _session.getId());
            
            response.setInResponseTo(_sRequestID);
            
            response.setDestination(sDestination);
                        
            IssuerBuilder issuerBuilder = (IssuerBuilder)_builderFactory.getBuilder(
                Issuer.DEFAULT_ELEMENT_NAME);
            Issuer issuer = issuerBuilder.buildObject();
            
            //if no format is set then NameID.ENTITY is in effect (saml-core-2.0-os r526)
            if (_sShadowedEntityId != null) {
            	issuer.setValue(_sShadowedEntityId);
            } else {
            	issuer.setValue(_sEntityID);
            }
            response.setIssuer(issuer);
            
            //set response status
            Status status = constructStatusCode(sTopLevelStatusCode, 
                sSecondLevelStatusCode);
            response.setStatus(status); 
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during response creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return response;
    }
    
    /**
     * Initialize the instance from the Session context
     * @param session Asimba Session in which the Request handling takes place
     */
    private void readSessionAttributes(ISession session)
    {
        if (session != null) {
            ISessionAttributes attributes = session.getAttributes();
            if (attributes.contains(AbstractAuthenticationRequestProtocol.class, SESSION_REQUEST_ID)) {
                _sRequestID = (String)attributes.get(AbstractAuthenticationRequestProtocol.class, 
                    SESSION_REQUEST_ID);
            }
            
            // try to establish a shadowed EntityId, only if feature is enabled
            if (_bEnableShadowIdp) {
	            if (attributes.contains(ProxyAttributes.class, ProxyAttributes.PROXY_SHADOWED_ENTITYID)) {
	            	_sShadowedEntityId = (String) attributes.get(ProxyAttributes.class, ProxyAttributes.PROXY_SHADOWED_ENTITYID);
	            	_logger.debug("Enabling Authn Request ShadowedEntityId support (shadowed entityId: "+_sShadowedEntityId+")");
	            }
            }
        }
    }
}
