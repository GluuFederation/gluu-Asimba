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

import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.GetComplete;
import org.opensaml.saml2.core.IDPEntry;
import org.opensaml.saml2.core.IDPList;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.RequesterID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Scoping;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthenticatingAuthorityBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.ChainingMetadataProvider;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.util.saml2.NameIDFormatter;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.SAML2Requestor;
import com.alfaariss.oa.util.saml2.StatusException;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;
import com.alfaariss.oa.util.saml2.proxy.ProxyAttributes;
import com.alfaariss.oa.util.saml2.proxy.SAML2IDPEntry;

/**
 * SAML2 Authentication Request Protocol.
 *
 * @author MHO
 * @author Alfa & Ariss
 */
public class AuthenticationRequestProtocol extends AbstractAuthenticationRequestProtocol
{
    /** urn:oasis:names:tc:SAML:2.0:cm:bearer */
    public final static String SAML2_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    /** AssertionConsumerServiceURL */
    public final static String SESSION_REQUEST_ASSERTION_CONSUMER_SERVICE_URL = "AssertionConsumerServiceURL";
    /** ProtocolBinding */
    public final static String SESSION_REQUEST_PROTOCOLBINDING = "ProtocolBinding";
    /** NameIDFormat */
    public final static String SESSION_REQUEST_NAMEIDFORMAT = "NameIDFormat";
    /** SPNameQualifier */
    public final static String SESSION_REQUEST_SPNAMEQUALIFIER = "SPNameQualifier";
    
    private Log _logger;
    private String _sBindingURI;
    private String _sNameIDFormat;
    private String _sAssertionConsumerServiceURL;
    private String _sSPNameQualifier;
    private NameIDFormatter _nameIDFormatter;
    private SAML2Requestor _saml2Requestor;
    private SPSSODescriptor _spSSODescriptor;
    private CryptoManager _cryptoManager;
    private boolean _bCompatible;
    
    /**
     * Creates the object.
     * @param session The session object.
     * @param nameIDFormatter the NameID Formatter object to check if a format 
     * is supported and to format the user id.
     * @param sProfileURL The profile URL
     * @param sEntityId The entity ID of the IDP
     * @param saml2Requestor SAML Requestor object
     * @param cryptoManager The OA CryptoManager
     * @param issueInstantWindow IssueInstant time window object
     * @param bCompatible TRUE if OA Server 1.5 compatible
     * @throws OAException If requestor metadata is invalid
     */
    public AuthenticationRequestProtocol(ISession session, 
        NameIDFormatter nameIDFormatter, String sProfileURL, String sEntityId, 
        SAML2Requestor saml2Requestor, CryptoManager cryptoManager, 
        SAML2IssueInstantWindow issueInstantWindow, boolean bCompatible) 
        throws OAException
    {
        super(cryptoManager.getSecureRandom(), sProfileURL, session, sEntityId, 
            issueInstantWindow);
        _logger = LogFactory.getLog(AuthenticationRequestProtocol.class);
        
        try
        {
            _sBindingURI = null;
            _sNameIDFormat = null;
            _sAssertionConsumerServiceURL = null;
            _sSPNameQualifier = null;
            _nameIDFormatter = nameIDFormatter;
            _saml2Requestor = saml2Requestor;
            _cryptoManager = cryptoManager;
            _bCompatible = bCompatible;
            
            if (_saml2Requestor != null)
            {
                ChainingMetadataProvider chainingMetadataProvider = 
                    _saml2Requestor.getChainingMetadataProvider();
                
                if (chainingMetadataProvider != null)
                {
                    _spSSODescriptor = 
                        (SPSSODescriptor)chainingMetadataProvider.getRole(
                            _saml2Requestor.getID(), 
                            SPSSODescriptor.DEFAULT_ELEMENT_NAME, 
                            SAMLConstants.SAML20P_NS);
                }
            }
            readSessionAttributes(session);
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during object creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Processes the AuthnRequest request object.
     * <br>
     * Verifies if the SAML AuthN Request is SAML 2 correct. 
     * @param request the AuthnRequest object.
     * @return ISession The updated session.
     * @throws OAException If an internal error occurred.
     * @throws StatusException If the request was invalid and a SAML response should be sent.
     */
    public ISession processRequest(RequestAbstractType request) 
        throws OAException, StatusException
    {
        try
        {
            AuthnRequest authnRequest = (AuthnRequest)request;
            
            ISessionAttributes oAttributes = _session.getAttributes();
            
            //first resolve the response, retrieve first so error responses can be sent
            resolveResponseTarget(authnRequest, oAttributes);
            
            processRequestAbstractType(request);
            
            Subject subject = authnRequest.getSubject();
            if (subject != null)
                processSubject(subject, oAttributes);
            
            resolveNameIDFormat(authnRequest, oAttributes);
                        
            RequestedAuthnContext requestedAuthnContext = authnRequest.getRequestedAuthnContext();
            if (requestedAuthnContext != null)
                resolveRequestedAuthnContext(requestedAuthnContext, oAttributes);
            
            Scoping scoping = authnRequest.getScoping();
            if (scoping != null)
                processRequestScoping(oAttributes, scoping);
            
            Boolean boolForced = authnRequest.isForceAuthn();
            if (boolForced != null)
            {
                _session.setForcedAuthentication(boolForced);
                _logger.debug("ForcedAuthentication: " + boolForced);
            }
            
            Boolean boolPassive = authnRequest.isPassive();
            if (boolPassive != null && boolPassive.booleanValue())
            {
                if (_bCompatible)
                {
                    _logger.debug("Passive: " + boolPassive);
                    _session.setPassive(boolPassive.booleanValue());
                }
                else
                {
                    _logger.debug("Unsupported Passive: " + boolPassive);
                    throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                        StatusCode.RESPONDER_URI, StatusCode.NO_PASSIVE_URI);
                }
            }
            
            Integer intAttributeConsumingServiceIndex = authnRequest.getAttributeConsumingServiceIndex();
            if (intAttributeConsumingServiceIndex != null)
            {
                oAttributes.put(ProxyAttributes.class, 
                    ProxyAttributes.ATTRIBUTE_CONSUMING_SERVICE_INDEX, 
                    intAttributeConsumingServiceIndex);
                _logger.debug("AttributeConsumingServiceIndex: " + intAttributeConsumingServiceIndex);
            }
            
            String providerName = authnRequest.getProviderName();
            if (providerName != null)
            {
                oAttributes.put(ProxyAttributes.class, 
                    ProxyAttributes.PROVIDERNAME, providerName);
                _logger.debug("ProviderName: " + providerName);
            }
        }
        catch (StatusException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during process", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return _session;
    }

    /**
     * Creates the SAML2 authentication response message.
     * 
     * @param tgt The TGT.
     * @param authnContextTypes The context types of the authentication profiles 
     *  the user is authenticated for.
     * @param attributes attributes that may be sent to the application (so ARP 
     * must be applied).
     * @param sAttributeNameFormatDefault The attribute nameformat for all attributes 
     *  in response.
     * @param htAttributeNameFormatMapper The attribute nameformat mapper.
     * @param sSessionIndex The session index that must be used in the response.
     * @param lExpirationOffset Expiration offset to be set as the not on or 
     *  after time in the response.
     * @param listAuthenticatingAuthorities A list with the Authenticating 
     *  authorities or NULL.
     * @return StatusResponseType If a SAML error response should be sent.
     * @throws OAException If an internal error occurred.
     */
    public StatusResponseType createResponse(ITGT tgt, List<String> authnContextTypes, 
        IAttributes attributes, String sAttributeNameFormatDefault, 
        Hashtable<String,String> htAttributeNameFormatMapper, 
        String sSessionIndex, long lExpirationOffset, 
        List<String> listAuthenticatingAuthorities) throws OAException
    {
        Response response = null;
        try
        {
            //read binding protocol that was set in process request  
            ISessionAttributes oAttributes = _session.getAttributes();
            if (oAttributes.contains(AuthenticationRequestProtocol.class, 
                SESSION_REQUEST_PROTOCOLBINDING))
            {
                _sBindingURI = (String)oAttributes.get(
                    AuthenticationRequestProtocol.class, 
                    SESSION_REQUEST_PROTOCOLBINDING);
            }
            
            ResponseBuilder builder = (ResponseBuilder)_builderFactory.getBuilder(
                Response.DEFAULT_ELEMENT_NAME);
            
            response = builder.buildObject();
    
            Assertion assertion = buildAssertion(tgt, authnContextTypes, 
                attributes, sAttributeNameFormatDefault, 
                htAttributeNameFormatMapper, sSessionIndex, 
                lExpirationOffset, listAuthenticatingAuthorities);
            
            if (_spSSODescriptor != null 
                && _spSSODescriptor.getWantAssertionsSigned())
            {
                Signature signature = createSignature();
                assertion.setSignature(signature);
                
                //update digest algorithm
                SAMLObjectContentReference contentReference = 
                    ((SAMLObjectContentReference)signature.getContentReferences().get(0));
                contentReference.setDigestAlgorithm(
                    SAML2CryptoUtils.getXMLDigestMethodURI(_cryptoManager.getMessageDigest()));
                
                signAssertion(assertion, signature);
            }
            
            response.getAssertions().add(assertion); 

            //add response defaults
            response = (Response)createResponse(_sAssertionConsumerServiceURL, 
                response, StatusCode.SUCCESS_URI);
        }
        catch (OAException e)
        {//When creating the error response message in here, the WebBrowserSSO can't react on this situation, which should lead to the removal of the alias and maybe even the removal of the TGT
            return null;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during response creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
            
        return response;
    }
    
    /**
     * Returns the value of the optional ProtocolBinding parameter in the request.
     * @return The binding URI or <code>null</code> if not specified in request.
     */
    public String getProtocolBinding()
    {
        return _sBindingURI;
    }
    
    /**
     * Returns the destination URL to send the response to.
     * @return The response Destination URL
     */
    public String getDestination()
    {
        return _sAssertionConsumerServiceURL;
    }
    
    /**
     * Returns the NameIDFormat that was supplied in the request.
     * 
     * @return The requested NameIDFormat or unspecified if none requested.
     * @since 1.2
     */
    public String getNameIDFormat()
    {
        return _sNameIDFormat;
    }
    
    /**
     * Returns the SPNameQualifier if supplied in the request.
     * @return SPNameQualifier or NULL if no SPNameQualifier was supplied in 
     * the request.
     * @since 1.2
     */
    public String getSPNameQualifier()
    {
        return _sSPNameQualifier;
    }
    
    private void processSubject(Subject subject, ISessionAttributes oAttributes) 
        throws StatusException, OAException
    {
        try
        {
            NameID nameID = subject.getNameID();
            if (nameID != null)
            {
                String sSPProvidedID = nameID.getSPProvidedID();
                if (sSPProvidedID != null)
                {
                    _logger.debug("Unsupported SPProvidedID in request: " + sSPProvidedID);
                    throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                        StatusCode.RESPONDER_URI, StatusCode.REQUEST_UNSUPPORTED_URI);
                }
                
                String sSPNameQualifier = nameID.getSPNameQualifier();
                if (sSPNameQualifier != null)
                {
                    _logger.debug("SPNameQualifier: " + sSPNameQualifier);
                    oAttributes.put(ProxyAttributes.class, 
                        ProxyAttributes.SUBJECT_SP_NAME_QUALIFIER, sSPNameQualifier);
                }
                
                String sNameQualifier = nameID.getNameQualifier();
                if (sNameQualifier != null)
                {
                    _logger.debug("NameQualifier: " + sNameQualifier);
                    oAttributes.put(ProxyAttributes.class, 
                        ProxyAttributes.SUBJECT_NAME_QUALIFIER, sNameQualifier);
                    
                    if (!sNameQualifier.equals(_sEntityID))
                    {
                        //TODO set as forced organization?
                    }
                }
                
                String sNameIDFormat = nameID.getFormat();
                if (sNameIDFormat != null)
                {
                    _logger.debug("NameIDFormat: " + sNameIDFormat);
                    oAttributes.put(ProxyAttributes.class, 
                        ProxyAttributes.SUBJECT_NAME_FORMAT, sNameIDFormat);
                }
    
                String sNameID = nameID.getValue();
                if (sNameID != null)
                {
                    _logger.debug("NameID: " + sNameID);
                    oAttributes.put(ProxyAttributes.class, 
                        ProxyAttributes.SUBJECT_NAMEID, sNameID);
                }
                
                if (sNameID != null)
                {
                    if (sNameIDFormat == null || 
                        !_nameIDFormatter.exists(sNameIDFormat, _session.getRequestorId(), sNameID))
                    {//DD set the nameid as force user id
                        _logger.debug("Setting forced user ID: " + sNameID);
                        _session.setForcedUserID(sNameID);
                    }
                    else
                    {//DD Supplied NameID is a TGT alias, so no forced userID must be set
                        _logger.debug("Supplied NameID is a TGT alias and must be set as forced user ID: " + sNameID);
                    }
                }
            }
        }
        catch (StatusException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during subject processing", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private void resolveRequestedAuthnContext(RequestedAuthnContext 
        requestedAuthnContext, ISessionAttributes oAttributes) throws StatusException
    {
        AuthnContextComparisonTypeEnumeration authnContextComparisonTypeEnumeration = requestedAuthnContext.getComparison();
        if (authnContextComparisonTypeEnumeration != null)
        {//DD: add Comparison value as session attribute for proxy modus
            oAttributes.put(ProxyAttributes.class, 
                ProxyAttributes.AUTHNCONTEXT_COMPARISON_TYPE, authnContextComparisonTypeEnumeration.toString());
            _logger.debug("Using requested RequestedAuthnContext Comparison: " 
                + authnContextComparisonTypeEnumeration);
        }
        
        //TODO (MHO) Add optional support RequestedAuthnContext support. (Force AuthN Profiles and Update session state)
        List<AuthnContextClassRef> listClassRefs = 
            requestedAuthnContext.getAuthnContextClassRefs();
        if (listClassRefs.size() > 0)
        {
            List<String> listSupportedClassRefs = new Vector<String>();
            
            for (AuthnContextClassRef acClassRef: listClassRefs)
            {
                String sClassRef = acClassRef.getAuthnContextClassRef();
                if (sClassRef != null)
                {
                    listSupportedClassRefs.add(sClassRef);
                }
                else if (sClassRef != null)
                {
                    _logger.debug("Requested RequestedAuthnContext not supported: " 
                        + sClassRef);
                }
            }
            
            if (listSupportedClassRefs.size() == 0)
            {
                _logger.debug("Requested RequestedAuthnContext ClassRefs not supported: " 
                    + listSupportedClassRefs);
                throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                    StatusCode.RESPONDER_URI, StatusCode.NO_AUTHN_CONTEXT_URI);
            }
            
            //DD Only add the supplied ClassRefs for using in proxy modus 
            oAttributes.put(ProxyAttributes.class, 
                ProxyAttributes.AUTHNCONTEXT_CLASS_REFS, listSupportedClassRefs);
            
            _logger.debug("Using requested RequestedAuthnContext ClassRefs: " 
                + listSupportedClassRefs);
        }
        
        List<AuthnContextDeclRef> listDeclRefs = 
            requestedAuthnContext.getAuthnContextDeclRefs();
        if (listDeclRefs.size() > 0)
        {
            List<String> listSupportedDeclRefs = new Vector<String>();
            
            for (AuthnContextDeclRef acDeclRef: listDeclRefs)
            {
                String sDeclRef = acDeclRef.getAuthnContextDeclRef();
                if (sDeclRef != null && sDeclRef.equals(AuthnContext.UNSPECIFIED_AUTHN_CTX))
                {
                    listSupportedDeclRefs.add(sDeclRef);
                }
                else if (sDeclRef != null)
                {
                    _logger.debug("Requested RequestedAuthnContext AuthnContextDeclRef not supported: " 
                        + acDeclRef.getAuthnContextDeclRef());
                }
            }
            
            if (listSupportedDeclRefs.size() == 0)
            {
                _logger.debug("Requested RequestedAuthnContext DeclRefs not supported: " 
                    + listSupportedDeclRefs);
                throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                    StatusCode.RESPONDER_URI, StatusCode.NO_AUTHN_CONTEXT_URI);
            }
            
            _logger.debug("Using requested RequestedAuthnContext DeclRefs: " 
                + listSupportedDeclRefs);
        }
    }
    
    private void resolveNameIDFormat(AuthnRequest authnRequest, 
        ISessionAttributes oAttributes) throws StatusException
    {
        NameIDPolicy nameIDPolicy = authnRequest.getNameIDPolicy();
        if (nameIDPolicy != null)
        { 
            _sSPNameQualifier = nameIDPolicy.getSPNameQualifier();
            if (_sSPNameQualifier != null)
            {
                _logger.debug("SPNameQualifier: " + _sSPNameQualifier);
                oAttributes.put(AuthenticationRequestProtocol.class, 
                    SESSION_REQUEST_SPNAMEQUALIFIER, _sSPNameQualifier);
            }
            
            Boolean boolAllowCreate = nameIDPolicy.getAllowCreate();
            if (boolAllowCreate != null)
            {
                _logger.debug("NameIDPolicy AllowCreate in request: : " 
                    + boolAllowCreate);
                
                oAttributes.put(ProxyAttributes.class, 
                    ProxyAttributes.ALLOW_CREATE, boolAllowCreate);
            }

            _sNameIDFormat = nameIDPolicy.getFormat();
            if (_sNameIDFormat != null)
            {
                if (!_nameIDFormatter.isSupported(_sNameIDFormat))
                {
                    _logger.debug("Unsupported NameID Format in NameIDPolicy: " 
                        + _sNameIDFormat);
                    throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                        StatusCode.REQUESTER_URI, StatusCode.INVALID_NAMEID_POLICY_URI);
                }
            }
        }
        
        if (_sNameIDFormat == null)
        {
            _sNameIDFormat = _nameIDFormatter.getDefault();
            _logger.debug("No NameID Format specified by requestor, using: " 
                + _sNameIDFormat);
        }
        else
            _logger.debug("Using NameID Format: " + _sNameIDFormat);
        
        oAttributes.put(AuthenticationRequestProtocol.class, 
            SESSION_REQUEST_NAMEIDFORMAT, _sNameIDFormat);
    }
    
    private void resolveResponseTarget(AuthnRequest authnRequest, 
        ISessionAttributes oAttributes) throws StatusException
    {
        String sAssertionConsumerServiceURL = authnRequest.getAssertionConsumerServiceURL();
        if (sAssertionConsumerServiceURL != null)
        {
            //The supplied value must associate with the requestor, 
            //it can be trusted if request is signed or value is available 
            //in SP metadata (saml-core-2.0-os r2061)
            if (!authnRequest.isSigned())
            {
                if (_spSSODescriptor != null)
                {
                    List<AssertionConsumerService> listACS = 
                        _spSSODescriptor.getAssertionConsumerServices();
                    for (AssertionConsumerService acs: listACS)
                    {
                        String sResponseLocation = acs.getResponseLocation();
                        if (sAssertionConsumerServiceURL.equals(acs.getLocation()))
                        {
                            _sAssertionConsumerServiceURL = sResponseLocation;
                            if (_sAssertionConsumerServiceURL == null)
                                _sAssertionConsumerServiceURL = sAssertionConsumerServiceURL;
                            break;
                        }
                        else if (sResponseLocation != null && 
                            sAssertionConsumerServiceURL.equals(sResponseLocation))
                        {
                            _sAssertionConsumerServiceURL = sAssertionConsumerServiceURL;
                            break;
                        }
                    }
                }
                
                if (_sAssertionConsumerServiceURL == null)
                {
                    StringBuffer sbError = 
                        new StringBuffer("Can't trust AssertionConsumerServiceURL '" );
                    sbError.append(sAssertionConsumerServiceURL);
                    sbError.append("' supplied in request: ");
                    sbError.append(authnRequest.getID());
                    _logger.debug(sbError.toString());
                }
            }
            else
                _sAssertionConsumerServiceURL = sAssertionConsumerServiceURL;
        }
        
        _sBindingURI = authnRequest.getProtocolBinding();
        
        if (_sAssertionConsumerServiceURL == null)
        {
            if (_spSSODescriptor == null)
            {
                _logger.debug(
                    "No SPSSODescriptor in metadata: Can't resolve response target for request: " 
                    + authnRequest.getID());
                
                throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                    StatusCode.RESPONDER_URI);                 
            }
            
            Integer intAssertionConsumerServiceIndex = 
                authnRequest.getAssertionConsumerServiceIndex();
            if (intAssertionConsumerServiceIndex != null)
            {
                List<AssertionConsumerService> listACS = 
                    _spSSODescriptor.getAssertionConsumerServices();
                if (listACS == null)
                {
                    _logger.debug("No AssertionConsumerServices in metadata for requestor: " 
                        + _session.getRequestorId());
                    throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                        StatusCode.RESPONDER_URI);      
                }
                
                AssertionConsumerService acs = null;

                for (AssertionConsumerService acsCandidate : listACS)
                {
                    if (intAssertionConsumerServiceIndex.equals(acsCandidate.getIndex()))
                    {
                        acs = acsCandidate;
                        break;
                    }
                }

                if (acs == null)
                {
                    StringBuffer sbError = 
                        new StringBuffer("Invalid AssertionConsumerServiceIndex '" );
                    sbError.append(intAssertionConsumerServiceIndex);
                    sbError.append("' supplied in request: ");
                    sbError.append(authnRequest.getID());
                    _logger.debug(sbError.toString());
                    
                    throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                        StatusCode.RESPONDER_URI);
                }
                
                _sAssertionConsumerServiceURL = acs.getResponseLocation();
                if (_sAssertionConsumerServiceURL == null)
                {
                    _sAssertionConsumerServiceURL = acs.getLocation();
                    _logger.debug("No 'ResponseLocation' found, using Location: " 
                        + _sAssertionConsumerServiceURL);
                }
                _sBindingURI = acs.getBinding();
            }
            else
            {
                AssertionConsumerService acs = 
                    _spSSODescriptor.getDefaultAssertionConsumerService();
                if (acs == null)
                {
                    _logger.debug(
                        "No default AssertionConsumerServices in metadata for requestor: " 
                        + _session.getRequestorId());
                    throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                        StatusCode.RESPONDER_URI);      
                }
                
                _sAssertionConsumerServiceURL = acs.getResponseLocation();
                if (_sAssertionConsumerServiceURL == null)
                {
                    _sAssertionConsumerServiceURL = acs.getLocation();
                    _logger.debug("No 'ResponseLocation' found, using Location: " 
                        + _sAssertionConsumerServiceURL);
                }
                _sBindingURI = acs.getBinding();
            }
        }
        
        if (_sAssertionConsumerServiceURL != null)
        {
            oAttributes.put(AuthenticationRequestProtocol.class, 
                SESSION_REQUEST_ASSERTION_CONSUMER_SERVICE_URL,
                _sAssertionConsumerServiceURL);
            
            _logger.debug("AssertionConsumerServiceURL: " + 
                _sAssertionConsumerServiceURL);
        }
        else
        {
            _logger.debug(
                "No AssertionConsumerServiceURL as target for response available for request: " 
                + authnRequest.getID());
            throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                StatusCode.RESPONDER_URI);
        }
        
        if (_sBindingURI != null)
        {
            oAttributes.put(AuthenticationRequestProtocol.class, 
                SESSION_REQUEST_PROTOCOLBINDING, _sBindingURI);
            
            _logger.debug("ProtocolBinding: " + _sBindingURI);
        }
        else
        {
            _logger.debug(
                "No ProtocolBinding for response available for request: " 
                + authnRequest.getID());
            throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                StatusCode.RESPONDER_URI);
        }
    }

    private void readSessionAttributes(ISession session)
    {
        ISessionAttributes attributes = session.getAttributes();
        if (attributes.contains(AuthenticationRequestProtocol.class, 
            SESSION_REQUEST_ASSERTION_CONSUMER_SERVICE_URL))
        {
            _sAssertionConsumerServiceURL = (String)attributes.get(
                AuthenticationRequestProtocol.class, 
                SESSION_REQUEST_ASSERTION_CONSUMER_SERVICE_URL);
        }
        
        if (attributes.contains(AuthenticationRequestProtocol.class, 
            SESSION_REQUEST_PROTOCOLBINDING))
        {
            _sBindingURI = (String)attributes.get(
                AuthenticationRequestProtocol.class, 
                SESSION_REQUEST_PROTOCOLBINDING);
        }
        
        if (attributes.contains(AuthenticationRequestProtocol.class, 
            SESSION_REQUEST_NAMEIDFORMAT))
        {
            _sNameIDFormat = (String)attributes.get(
                AuthenticationRequestProtocol.class, 
                SESSION_REQUEST_NAMEIDFORMAT);
        }
        
        if (attributes.contains(AuthenticationRequestProtocol.class, 
            SESSION_REQUEST_SPNAMEQUALIFIER))
        {
            _sSPNameQualifier = (String)attributes.get(
                AuthenticationRequestProtocol.class, 
                SESSION_REQUEST_SPNAMEQUALIFIER);
        }
    }
    
    private void processRequestScoping(ISessionAttributes oAttributes, Scoping scoping) 
        throws StatusException, OAException
    {
        try
        {
            Integer intProxyCount = scoping.getProxyCount();
            if (intProxyCount != null)
            {
                oAttributes.put(ProxyAttributes.class, 
                    ProxyAttributes.PROXYCOUNT, intProxyCount);
                _logger.debug("ProxyCount: " + intProxyCount);
            }
            
            IDPList idpList = scoping.getIDPList();
            if (idpList != null)
            { 
                List<IDPEntry> listIDPEntrys = idpList.getIDPEntrys();
                if (listIDPEntrys != null)
                {
                    List<SAML2IDPEntry> listIDPs = new Vector<SAML2IDPEntry>();
                    Collection<String> colPreferredOrganizations = new Vector<String>();
                    for (IDPEntry entry: listIDPEntrys)
                    {
                        String sProviderID = entry.getProviderID();
                        if (sProviderID == null)
                        {
                            _logger.debug(
                                "No ProviderID in IDPEntry within request Scoping");
                            throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                                StatusCode.REQUESTER_URI);
                        }
                        
                        String sName = entry.getName();
                        String sLoc = entry.getLoc();
                        
                        SAML2IDPEntry saml2IDPEntry = new SAML2IDPEntry(
                            sProviderID, sName, sLoc);
                        listIDPs.add(saml2IDPEntry);
                        
                        colPreferredOrganizations.add(sProviderID);
                    }
                    
                    if (!listIDPs.isEmpty())
                    {
                        oAttributes.put(ProxyAttributes.class, 
                            ProxyAttributes.IDPLIST, listIDPs);
                        
                        _logger.debug("Forced IDPs: " + listIDPs);
                    }
                    
                    if (!colPreferredOrganizations.isEmpty())
                    {
                        oAttributes.put(
                            com.alfaariss.oa.util.session.ProxyAttributes.class, 
                            com.alfaariss.oa.util.session.ProxyAttributes.FORCED_ORGANIZATIONS, 
                            colPreferredOrganizations);
                        
                        _logger.debug("Preferred organizations: " + colPreferredOrganizations);
                    }
                }
                
                GetComplete getComplete = idpList.getGetComplete();
                if (getComplete != null)
                {
                    String sGetComplete = getComplete.getGetComplete();
                    oAttributes.put(ProxyAttributes.class, 
                        ProxyAttributes.IDPLIST_GETCOMPLETE, sGetComplete);
                    _logger.debug("GetComplete: " + sGetComplete);
                }
            }
            
            List<RequesterID> listRequesterIDs = scoping.getRequesterIDs();
            if (listRequesterIDs != null && listRequesterIDs.size() > 0)
            {
                List<String> listIDs = new Vector<String>();
                for (RequesterID requestor: listRequesterIDs)
                    listIDs.add(requestor.getRequesterID());    
                
                if (!listIDs.isEmpty())
                {
                    oAttributes.put(ProxyAttributes.class, 
                        ProxyAttributes.REQUESTORIDS, listIDs);
                    _logger.debug("RequesterIDs in request Scoping: " + listIDs);
                }
            }
        }
        catch (StatusException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during process", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private Assertion buildAssertion(ITGT tgt, List<String> authnContextTypes, 
        IAttributes attributes, String sAttributeNameFormat, 
        Hashtable<String,String> htAttributeNameFormatMapper,
        String sSessionIndex, long lExpirationOffset, 
        List<String> listAuthenticatingAuthorities) throws OAException
    {
        Assertion assertion = null;
        try
        {
            AssertionBuilder builder = (AssertionBuilder)_builderFactory.getBuilder(
                Assertion.DEFAULT_ELEMENT_NAME);
    
            // Create the assertion
            assertion = builder.buildObject();
            assertion.setVersion(SAMLVersion.VERSION_20);
            assertion.setID(sSessionIndex);
            assertion.setIssueInstant(new DateTime());
    
            Issuer issuer = buildIssuer(null, _sEntityID);
            assertion.setIssuer(issuer);
            
            DateTime dtNotOnOrAfter = new DateTime(System.currentTimeMillis() 
                + lExpirationOffset);
            
            String sTGTID = null;
            if (tgt != null)
                sTGTID = tgt.getId();
            
            String sNameID = 
                _nameIDFormatter.format(_session.getUser(), _sNameIDFormat, 
                    _session.getRequestorId(), sTGTID);
            Subject subject = buildSubject(sNameID, dtNotOnOrAfter);
            assertion.setSubject(subject);
                        
            DateTime dtAuthnStatementNotOnOrAfter = dtNotOnOrAfter;
            if (tgt != null)
                dtAuthnStatementNotOnOrAfter = new DateTime(tgt.getTgtExpTime());
            
            for (String authnContextType: authnContextTypes)
            {
                AuthnStatement authnStatement = buildAuthnStatement(sSessionIndex, 
                    dtAuthnStatementNotOnOrAfter, authnContextType, 
                    listAuthenticatingAuthorities);
                assertion.getAuthnStatements().add(authnStatement);
            }
            
            if (attributes.size() > 0)
            {
                AttributeStatement attributeStatement = 
                    buildAttributeStatement(attributes, sAttributeNameFormat, 
                        htAttributeNameFormatMapper);
                assertion.getAttributeStatements().add(attributeStatement);
            }
            
            Conditions conditions = buildConditions(dtNotOnOrAfter);
            assertion.setConditions(conditions);
        }
        catch (OAException e)
        {
            throw e;
        }
        
        return assertion;
    }
    
    /**
     * Creates a SAML Issuer object.
     * 
     * @param format The Issuer format.
     * @param value The issuer value.
     * @return Issuer The SAML ISsuer object.
     */
    private Issuer buildIssuer(String format, String value)
    {
        IssuerBuilder issuerBuilder = (IssuerBuilder)_builderFactory.getBuilder(
            Issuer.DEFAULT_ELEMENT_NAME);
        
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(value);
        
        //if format is null then NameID.ENTITY is in effect (saml-core-2.0-os r526)
        if (format != null)
            issuer.setFormat(format);
        
        return issuer;
    }
    
    private Conditions buildConditions(DateTime dtNotOnOrAfter)
    {
        AudienceRestrictionBuilder audienceRestrictionBuilder =
            (AudienceRestrictionBuilder)_builderFactory.getBuilder(
                AudienceRestriction.DEFAULT_ELEMENT_NAME);
        AudienceRestriction audienceRestriction = 
            audienceRestrictionBuilder.buildObject();
        AudienceBuilder audienceBuilder = 
            (AudienceBuilder)_builderFactory.getBuilder(
                Audience.DEFAULT_ELEMENT_NAME);
        Audience audience = audienceBuilder.buildObject();
        audience.setAudienceURI(_session.getRequestorId());
        audienceRestriction.getAudiences().add(audience); 
        
        ConditionsBuilder conditionsBuilder =
            (ConditionsBuilder)_builderFactory.getBuilder(
                Conditions.DEFAULT_ELEMENT_NAME);
        Conditions conditions = conditionsBuilder.buildObject();
        conditions.getAudienceRestrictions().add(audienceRestriction);
        
        conditions.setNotBefore(new DateTime()); 
        conditions.setNotOnOrAfter(new DateTime(dtNotOnOrAfter));
        
        return conditions;
    }
        
    private Subject buildSubject(String value, DateTime dtNotOnOrAfter) 
        throws OAException
    {
        NameIDBuilder nameIDBuilder = 
            (NameIDBuilder)_builderFactory.getBuilder(
                NameID.DEFAULT_ELEMENT_NAME);
        NameID nameID = nameIDBuilder.buildObject();
        
        if (_sNameIDFormat != null)
            nameID.setFormat(_sNameIDFormat);
        else
            nameID.setFormat(NameIDType.UNSPECIFIED);
        nameID.setValue(value);
        
        if (_sSPNameQualifier != null)
            nameID.setSPNameQualifier(_sSPNameQualifier);
        
        nameID.setNameQualifier(_sEntityID);
        
        SubjectBuilder subjectBuilder = 
            (SubjectBuilder)_builderFactory.getBuilder(
                Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameID);
        
        SubjectConfirmationBuilder confirmationBuilder = 
            (SubjectConfirmationBuilder)_builderFactory.getBuilder(
                SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        SubjectConfirmation subjectConfirmation = 
            confirmationBuilder.buildObject();
        subjectConfirmation.setMethod(SAML2_BEARER);
        
        SubjectConfirmationDataBuilder confirmationDataBuilder = 
            (SubjectConfirmationDataBuilder)_builderFactory.getBuilder(
                SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        SubjectConfirmationData subjectConfirmationData = 
            confirmationDataBuilder.buildObject();
        if (_sAssertionConsumerServiceURL != null)
            subjectConfirmationData.setRecipient(_sAssertionConsumerServiceURL);
        else
        {
            _logger.warn(
                "Can't set Recipient in confirmation data, no AssertionConsumerServiceURL available");
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        //DD Limit the window during which the assertion can be delivered (saml-profiles-2.0-os r556) 
        subjectConfirmationData.setNotOnOrAfter(dtNotOnOrAfter);
        subjectConfirmationData.setInResponseTo(_sRequestID);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        
        subject.getSubjectConfirmations().add(subjectConfirmation);
        return subject;
    }
    
    private AuthnStatement buildAuthnStatement(String sSessionIndex, 
        DateTime dtSessionNotOnOrAfter, String authnContextType, 
        List<String> listAuthenticatingAuthorities)
    {
        //Create the AuthnStatement
        AuthnStatementBuilder authnStatemenBuilder =
            (AuthnStatementBuilder)_builderFactory.getBuilder(
                AuthnStatement.DEFAULT_ELEMENT_NAME);
        AuthnStatement authnStatement = authnStatemenBuilder.buildObject();
        authnStatement.setAuthnInstant(new DateTime());
        authnStatement.setSessionIndex(sSessionIndex);
        authnStatement.setSessionNotOnOrAfter(dtSessionNotOnOrAfter);
        
        AuthnContextBuilder authnContextBuilder =
            (AuthnContextBuilder)_builderFactory.getBuilder(
                AuthnContext.DEFAULT_ELEMENT_NAME);
        AuthnContext authnContext = authnContextBuilder.buildObject();
                
        AuthnContextClassRefBuilder authnContextClassRefBuilder =
            (AuthnContextClassRefBuilder)_builderFactory.getBuilder(
                AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef authnContextClassRef = 
            authnContextClassRefBuilder.buildObject();
        authnContextClassRef.setAuthnContextClassRef(authnContextType);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        
        if (listAuthenticatingAuthorities != null)
        {//DD set the authenticating authority
            for (String sAuthorityURI: listAuthenticatingAuthorities)
            {
                AuthenticatingAuthorityBuilder authenticatingAuthorityBuilder = 
                    (AuthenticatingAuthorityBuilder)_builderFactory.getBuilder(
                        AuthenticatingAuthority.DEFAULT_ELEMENT_NAME);
                AuthenticatingAuthority authnticatingAuthority = authenticatingAuthorityBuilder.buildObject();
                authnticatingAuthority.setURI(sAuthorityURI);
                authnContext.getAuthenticatingAuthorities().add(authnticatingAuthority);
            }
        }
        
        authnStatement.setAuthnContext(authnContext);
        
        return authnStatement;
    }
    
    private AttributeStatement buildAttributeStatement(IAttributes attributes, 
        String sAttributeNameFormat, 
        Hashtable<String,String> htAttributeNameFormatMapper)
    {
        AttributeStatementBuilder attributeStatemenBuilder = 
            (AttributeStatementBuilder)_builderFactory.getBuilder(
                AttributeStatement.DEFAULT_ELEMENT_NAME);
        AttributeStatement attributeStatement = attributeStatemenBuilder.buildObject();
        
        AttributeBuilder attributeBuilder = 
            (AttributeBuilder)_builderFactory.getBuilder(
                Attribute.DEFAULT_ELEMENT_NAME);
        
        Enumeration<?> enumNames = attributes.getNames();
        while(enumNames.hasMoreElements())
        {
            String sName = (String)enumNames.nextElement();
            Attribute attribute = attributeBuilder.buildObject();
            attribute.setName(sName);
            
            //DD nameformat can be overwritten by a default or explicitly configured nameformat
            String sNameFormat = htAttributeNameFormatMapper.get(sName);
            if (sNameFormat == null)
            {
                if (sAttributeNameFormat != null && sAttributeNameFormat.trim().length() == 0)
                    sNameFormat = null;
                else if (sAttributeNameFormat != null)
                    sNameFormat = sAttributeNameFormat;
                else if (_bCompatible)
                    sNameFormat = attributes.getFormat(sName);
            }
            if (sNameFormat != null)
                attribute.setNameFormat(sNameFormat);
                        
            Object oValue = attributes.get(sName);
            if (oValue instanceof String)
            {
                XSStringBuilder stringBuilder = 
                    (XSStringBuilder)_builderFactory.getBuilder(XSString.TYPE_NAME);
                XSString stringValue = stringBuilder.buildObject(
                    AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                stringValue.setValue((String)oValue);
                attribute.getAttributeValues().add(stringValue);
            }
            else if(oValue instanceof List)
            {//multivalue attribute
                XSStringBuilder stringBuilder = 
                    (XSStringBuilder)_builderFactory.getBuilder(XSString.TYPE_NAME);
                List listValues = (List)oValue;
                Iterator iterValues = listValues.iterator();
                while (iterValues.hasNext())
                {
                    XSString stringValue = stringBuilder.buildObject(
                        AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                    stringValue.setValue((String)iterValues.next());
                    attribute.getAttributeValues().add(stringValue);
                }
            }
            else
            {
                StringBuffer sbDebug = new StringBuffer("Attribute '");
                sbDebug.append(sName);
                sbDebug.append("' has an unsupported value; is not a String: ");
                sbDebug.append(oValue);
                _logger.debug(sbDebug.toString());
            }
            attributeStatement.getAttributes().add(attribute);
        }
        
        return attributeStatement;
    }
    
    private Signature createSignature() 
        throws OAException, SecurityException
    {
        SignatureBuilder builder = 
            (SignatureBuilder)_builderFactory.getBuilder(
                Signature.DEFAULT_ELEMENT_NAME);   
        Signature signature = builder.buildObject(
            Signature.DEFAULT_ELEMENT_NAME); 
        
        signature.setSignatureAlgorithm(
            SAML2CryptoUtils.getXMLSignatureURI(_cryptoManager));
        
        //Get signing credentials
        X509Credential signingX509Cred = 
            SAML2CryptoUtils.retrieveMySigningCredentials(
                _cryptoManager, _sEntityID);                         
        signature.setSigningCredential(signingX509Cred);
              
        SecurityHelper.prepareSignatureParams(
            signature, signingX509Cred, null, null);
        
        return signature;
    }
    
    private void signAssertion(
        Assertion assertion, Signature signature) throws OAException
    {        
        try
        {           
            //Marshall 
            Marshaller marshaller = Configuration.getMarshallerFactory(
                ).getMarshaller(assertion);
            if (marshaller == null) 
            {
                _logger.error("No marshaller registered for " + 
                    assertion.getElementQName() + 
                    ", unable to marshall assertion");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            if(assertion.getDOM() == null)
                marshaller.marshall(assertion);
            
            Signer.signObject(signature);
        }
        catch (OAException e) 
        {
             throw e;
        }
        catch (MarshallingException e)
        {
            _logger.warn(
                "Marshalling error while signing assertion request", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch(Exception e)
        {
            _logger.error("Could not sign assertion", e);
            throw new OAException(SystemErrors.ERROR_INIT);
        }
    }
}
