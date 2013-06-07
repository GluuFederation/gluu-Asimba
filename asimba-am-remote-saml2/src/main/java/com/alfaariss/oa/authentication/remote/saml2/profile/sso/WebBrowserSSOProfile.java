/*
 * Asimba - Serious Open Source SSO
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2011 Alfa & Ariss B.V.
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
package com.alfaariss.oa.authentication.remote.saml2.profile.sso;

import java.util.Collection;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.assertion.SAML2TimestampWindow;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Scoping;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.credential.Credential;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.idmapper.IIDMapper;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.authentication.remote.saml2.SAML2AuthNConstants;
import com.alfaariss.oa.authentication.remote.saml2.beans.SAMLRemoteUser;
import com.alfaariss.oa.authentication.remote.saml2.profile.AbstractAuthNMethodSAML2Profile;
import com.alfaariss.oa.authentication.remote.saml2.util.ResponseValidator;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;
import com.alfaariss.oa.engine.user.provisioning.translator.standard.StandardProfile;
import com.alfaariss.oa.util.saml2.SAML2ConditionsWindow;
import com.alfaariss.oa.util.saml2.SAML2Exchange;
import com.alfaariss.oa.util.saml2.SAML2SecurityException;
import com.alfaariss.oa.util.saml2.binding.AbstractEncodingFactory;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;
import com.alfaariss.oa.util.saml2.proxy.ProxyAttributes;

/**
 * Handler for the SAML2 Web browser SSO profile.
 *
 * @author jre
 * @author Alfa & Ariss
 */
public class WebBrowserSSOProfile extends AbstractAuthNMethodSAML2Profile
{   
    /** Logger */
    protected static Log _logger;
    /** SP SSO Descriptor */
    protected SPSSODescriptor _spSSODescriptor;
    /** Configured AuthnContext Comparison */
    protected String _sAuthnContextComparison;
    /** Configured AuthnContext ClassRefs */
    protected List<String> _listAuthnContextClassRefs;
    /** Secure Random ID Generator */
    protected SecureRandomIdentifierGenerator _idGenerator;
    
    /**
     * Default constructor. 
     */
    public WebBrowserSSOProfile()
    {
        _logger = LogFactory.getLog(this.getClass());
        _sAuthnContextComparison = null;
        _listAuthnContextClassRefs = new Vector<String>();
    }
    
    /**
     * @see com.alfaariss.oa.authentication.remote.saml2.profile.AbstractAuthNMethodSAML2Profile#init(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element, org.opensaml.saml2.metadata.EntityDescriptor, com.alfaariss.oa.api.idmapper.IIDMapper, com.alfaariss.oa.engine.core.idp.storage.IIDPStorage, java.lang.String, com.alfaariss.oa.util.saml2.SAML2ConditionsWindow)
     */
    public void init(IConfigurationManager configurationManager, Element config,
        EntityDescriptor entityDescriptor, IIDMapper mapper, 
        IIDPStorage orgStorage, String sMethodID, 
        SAML2ConditionsWindow conditionsWindow,
        SAML2TimestampWindow oAuthnInstant,
        StandardProfile oRemoteSAMLUserProvisioningProfile) throws OAException
    {
        super.init(configurationManager,config,entityDescriptor,mapper,orgStorage,sMethodID,conditionsWindow, 
        		oAuthnInstant, oRemoteSAMLUserProvisioningProfile);
        
        //check if OA Server 1.5 is used
        _bCompatible =  isCompatible();
        _logger.info("Optional user attribute name format: " + (_bCompatible ? "supported" : "not supported"));
        
        _spSSODescriptor = _entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        
        Element eAuthnContext = configurationManager.getSection(config, "AuthnContext");
        if (eAuthnContext == null)
        {
            _logger.info("No optional 'AuthnContext' section found in configuration");
            _sAuthnContextComparison = null;
            _listAuthnContextClassRefs = new Vector<String>();
        }
        else
        {
            readAuthnContextConfig(configurationManager, eAuthnContext);
        }
    }
    
    /**
     * Processes the event according to the implemented profile.
     *
     * @param request The HTTP request.
     * @param response The HTTP response.
     * @param session The Authentication Session.
     * @param organization The SAML organization.
     * @param attributeMapper The Table with attributes.
     * 
     * @return The resulting User event.
     * @throws OAException If an error occurs.
     */
    @SuppressWarnings("unchecked") // for retrieval of session attributes
    public UserEvent process(HttpServletRequest request, HttpServletResponse response,
        ISession session, SAML2IDP organization, 
        Hashtable<String, String> attributeMapper) throws OAException
    {
        _logger.debug("Request recieved: " + request.getRequestURL().toString());
        
        Boolean boolResponse = (Boolean)request.getAttribute(SAML2AuthNConstants.RESPONSE_ENDPOINT_PARAM);
        if (boolResponse != null && boolResponse)
        {
            return handleResponse(request, session, organization, attributeMapper);
        }
        
        return createAuthNRequest(request, response, session, 
            organization);
    }

    /**
     * Creates and sends the SAML2 AuthnRequest to the supplied IdP.
     *  
     * @param servletRequest Servlet Request
     * @param servletResponse Selvet Response
     * @param session AuthN session
     * @param organization Target IdP
     * @return User Event
     * @throws OAException If authnrequest could not be send
     */
    protected UserEvent createAuthNRequest(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse, ISession session,
        SAML2IDP organization) throws OAException
    {
        try
        {
            IDPSSODescriptor descriptor = getIdPDescriptor(organization);
            String sSupportedBinding = getSupportedBinding(descriptor);
            if (sSupportedBinding == null)
            {
                _logger.error("Authentication request could not be formed, since no suitable binding can be found");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            _logger.debug("Using binding: " + sSupportedBinding);
            
            String sDestination = null;
            
            for (SingleSignOnService service : descriptor.getSingleSignOnServices())
            {
                if (service.getBinding().equals(sSupportedBinding))
                {
                    sDestination = service.getLocation();
                }
            }
           
            AuthnRequest request = buildAuthnRequest();
            
            ISessionAttributes sessionAttributes = session.getAttributes();
            String requestID = generateRequestID(session.getId(), sessionAttributes);
            request.setID(requestID);
            
            //Add AssertionConsumerService
            
            if (_spSSODescriptor != null)
            {
                AssertionConsumerService acs = _spSSODescriptor.getDefaultAssertionConsumerService();
                if (acs != null)
                {
                    Integer intIndex = acs.getIndex();
                    String sLocation = acs.getLocation();
                    String sBinding = acs.getBinding();
                    if (intIndex != null && organization.useACSIndex() != null && organization.useACSIndex())
                    {
                        request.setAssertionConsumerServiceIndex(intIndex);
                    }
                    else if (sLocation != null && sBinding != null)
                    {//If the AssertionConsumerServiceIndex can't be set, the following info should be set:
                        request.setAssertionConsumerServiceURL(sLocation);
                        request.setProtocolBinding(sBinding);
                    }
                }
            }
            
            request.setDestination(sDestination);
            request.setIssueInstant(new DateTime());
            
            Issuer issuer = buildIssuer();
            request.setIssuer(issuer);
            
            //NameIDPolicy
            if (organization.useNameIDPolicy() != null && organization.useNameIDPolicy())
            {
                NameIDPolicy nidp = buildNameIDPolicy(session, descriptor, 
                    organization.useAllowCreate(), organization.getNameIDFormat());
                if (nidp != null)
                    request.setNameIDPolicy(nidp);
            }
            
            IUser user = session.getUser();
            String sRequestUID = session.getForcedUserID();
            if (user != null)
                sRequestUID = user.getID();
            
            if (sRequestUID != null)
            {           
                String sNameQualifier = _entityDescriptor.getEntityID();
                String sNameIDFormat = NameIDType.UNSPECIFIED;
                if (user instanceof SAMLRemoteUser)
                {
                    SAMLRemoteUser samlUser = ((SAMLRemoteUser)user);
                    sNameIDFormat = samlUser.getFormat();
                    
                    //the namequalifier that was returned by the remote SAML 
                    //organization is set as the organization of the remote 
                    //SAML user; this way the organization is set as name qualifier
                    sNameQualifier = samlUser.getOrganization();
                }
                else
                {
                    String sProxyNameID = (String)sessionAttributes.get(ProxyAttributes.class, ProxyAttributes.SUBJECT_NAMEID);
                    if (sProxyNameID != null && sProxyNameID.equals(session.getForcedUserID()))
                    {//Check if the force user id is supplied by the requestor (SAML2) 
                        
                        String sProxyNameIDFormat = (String)sessionAttributes.get(ProxyAttributes.class, ProxyAttributes.SUBJECT_NAME_FORMAT);
                        if (sProxyNameIDFormat != null)
                            sNameIDFormat = sProxyNameIDFormat;
                        
                        String sProxyNameQualifier = (String)sessionAttributes.get(ProxyAttributes.class, ProxyAttributes.SUBJECT_NAME_QUALIFIER);
                        if (sProxyNameQualifier != null)
                            sNameQualifier = sProxyNameQualifier;
                    }
                }
                
                Subject subject = buildSubject(sRequestUID, sNameIDFormat, 
                    sNameQualifier);
                if (subject != null)
                    request.setSubject(subject);
            }
            
            
            //Scoping
            if (organization.useScoping() != null && organization.useScoping())
            {
                Scoping scop = buildScoping(sessionAttributes, session.getRequestorId());
                if (scop != null)
                    request.setScoping(scop);
            }
            
            //TODO is the forceAuthN parameter for the session also valid for remote authNs? 
            request.setForceAuthn(session.isForcedAuthentication());
                        
            String sProviderName = (String)sessionAttributes.get(
                ProxyAttributes.class, ProxyAttributes.PROVIDERNAME);
            if (sProviderName != null)
            {
                request.setProviderName(sProviderName);
            }
            else
            {//DD set ProviderName with requestor name if not supplied in AuthnRequest
                IRequestor requestor = _requestorPoolFactory.getRequestor(session.getRequestorId());
                if (requestor != null)
                {
                    String sFriendlyName = requestor.getFriendlyName();
                    if (sFriendlyName != null && sFriendlyName.length() > 0)
                        request.setProviderName(sFriendlyName);
                }
            }
            
            //DD proxy the optionally available authncontext
            RequestedAuthnContext requestedAuthnContext = buildRequestedAuthnContext(sessionAttributes);
            if (requestedAuthnContext != null)
                request.setRequestedAuthnContext(requestedAuthnContext);
            
            AbstractEncodingFactory encFactory = 
                AbstractEncodingFactory.createInstance(
                    servletRequest, servletResponse, sSupportedBinding,
                    SAML2Exchange.getSPSSOBindingProperties());
            
            if (encFactory == null)
            {
                _logger.error("No encoding factory available for request");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
            context = createEncodingContext(servletRequest, servletResponse);

            context.setInboundMessageIssuer(organization.getID());
            context.setOutboundMessageIssuer(_entityDescriptor.getEntityID());
            context.setLocalEntityId(_entityDescriptor.getEntityID());
            context.setLocalEntityMetadata(_entityDescriptor);
            context.setLocalEntityRoleMetadata(_entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS));
            context.setMetadataProvider(organization.getMetadataProvider());

            context.setOutboundSAMLMessage(request);
            
            Endpoint endPoint = buildMetadataEndpoint(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME, sSupportedBinding, 
                sDestination, null);
            context.setPeerEntityEndpoint(endPoint);

            if (_signingEnabled)
            {
                Credential credentials = SAML2CryptoUtils.retrieveMySigningCredentials(
                    _crypto, _entityDescriptor.getEntityID());  
                context.setOutboundSAMLMessageSigningCredential(credentials);
            }
            else if (_spSSODescriptor.isAuthnRequestsSigned() || descriptor.getWantAuthnRequestsSigned())
            {
                _logger.warn("Could not sign AuthnRequest: no private key available");
            }
            
            SAMLMessageEncoder encoder = encFactory.getEncoder();
            
            //session must be persisted before sending the request.
            session.persist();
            
            encoder.encode(context);
            
            if (_logger.isDebugEnabled())
            {
                XMLObject xmlObject = context.getOutboundSAMLMessage();
                if (xmlObject != null)
                    logXML(xmlObject);
            }
            
            return UserEvent.AUTHN_METHOD_IN_PROGRESS;
        }
        catch(OAException e)
        {
            throw e;
        }
        catch (MessageEncodingException e)
        {
            _logger.error("Encoding of authentication request failed", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Processes the SAML2 AuthnResponse.
     *  
     * @param request Servlet request object
     * @param session AuthN session
     * @param authnSessionOrganization IdP who was selected to provide the response
     * @param attributeMapper Optional attribute mapper object
     * @return User Event
     * @throws OAException If response handling results in an internal error.
     */
    @SuppressWarnings({"unchecked"})
    protected UserEvent handleResponse(HttpServletRequest request, ISession session,
        SAML2IDP authnSessionOrganization, Hashtable<String, String> attributeMapper) 
        throws OAException
    {
        //SAML Response handling.
        
        StatusResponseType respMsg = null;
        SAML2IDP samlResponseOrganization = null;
        
        //Initialize validator for responses
        ResponseValidator validator  = null;
        
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> context = 
            (SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject>)
            request.getAttribute(SAML2AuthNConstants.SESSION_ATTRIBUTE_NAME);
        try
        {

            if (context == null) 
            {
                _logger.debug("No context available in request as attribute with name: " 
                    + SAML2AuthNConstants.SESSION_ATTRIBUTE_NAME);
                return UserEvent.AUTHN_METHOD_FAILED;
            }
            
            respMsg = (Response)context.getInboundSAMLMessage();
            
            if (_logger.isDebugEnabled())
            {
                XMLObject xmlObject = context.getInboundSAMLMessage();
                if (xmlObject != null)
                    logXML(xmlObject);
            }
            
            //Resolve Issuer
            String sOrgID = context.getInboundMessageIssuer();
            if (authnSessionOrganization.getID().equals(sOrgID)) {
                samlResponseOrganization = authnSessionOrganization;
            } else {
                _logger.debug("Response issuer was not the same as who the AuthnRequest was sent to.");
                return UserEvent.AUTHN_METHOD_FAILED;
            }
            
            //Response signing is not mandatory
            validator = new ResponseValidator
                (_entityDescriptor.getEntityID(), samlResponseOrganization, false);
            validator.validateResponse(context);
        }
        catch (ClassCastException e)
        {
            _logger.debug("Illegally typed object retrieved from session", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (SAML2SecurityException e)
        {
            _logger.debug("Validation of incoming SAML message failed", e);
            return UserEvent.AUTHN_METHOD_FAILED;
        }
        
        if (respMsg == null)
        {
            _logger.debug("Could not fetch response from session");
            return UserEvent.AUTHN_METHOD_FAILED;
        }
        
        //the status
        UserEvent evt = getStatus(respMsg.getStatus(), authnSessionOrganization);
        if (evt != UserEvent.AUTHN_METHOD_SUCCESSFUL)
        {
            _logger.debug("Message indicated that the authentication was not successful: " + evt);
            return evt;
        }
        
        //Response handling:
        //DD: Artifact response type should not be known here, but until libraries provide a good implementation we leave it here.
        Response resp = null;
        if (respMsg instanceof Response)
        {
            resp = (Response)respMsg;
        }
        else if (respMsg instanceof ArtifactResponse)
        {
            SAMLObject msg = ((ArtifactResponse)respMsg).getMessage();
            if (msg instanceof Response)
            {
                resp = (Response)msg;
                if (!validator.validateMessage(context, resp)) //Extra validation
                {
                    _logger.debug("Response in ArtifactResponse signature validation failure");
                    return UserEvent.AUTHN_METHOD_FAILED;
                }
                UserEvent event = getStatus(resp.getStatus(), authnSessionOrganization);
                if (event != UserEvent.AUTHN_METHOD_SUCCESSFUL)
                {
                    _logger.debug("Message (in artifact response) indicated that the authentication was not successful: " + event);
                    return event;
                }
            }
            else
            {
                _logger.debug("Artifact response did not contain a Response message: received " + msg.getElementQName());
            }
        }
        
        if (resp == null)
        {
            _logger.debug("Response message did not contain 'Response' or 'ArtifactResponse' XML object");
            return UserEvent.AUTHN_METHOD_FAILED;
        }
        
        //handle assertions
        List<Assertion> assertions = resp.getAssertions();
        
        if (assertions.isEmpty())
        {
            _logger.debug("Response contains no (unencrypted) assertions");
            return UserEvent.AUTHN_METHOD_FAILED;
        }
        
        Assertion assertion = null;
        
        Collection<String> cForcedOrgs = (Collection<String>)session.getAttributes()
            .get(SAML2AuthNConstants.class, SAML2AuthNConstants.FORCED_ORGANIZATIONS);
        
        //DD The first assertion that does not have an issuer, or known issuer will be processed
        for (Assertion as : assertions)
        {
            SAML2IDP tmpReq = null;
            Issuer asIssuer = as.getIssuer();
            String sIssuer = (asIssuer != null ? asIssuer.getValue() : null);
            if (sIssuer != null && !sIssuer.equals(authnSessionOrganization.getID()))
            {
                //Proxied assertion, check organizations
                SAML2IDP forcedOrg = (SAML2IDP)_organizationStorage.getIDP(sIssuer);
                if (forcedOrg != null) //org found locally
                {
                    tmpReq = forcedOrg;                    
                }
                else if(cForcedOrgs != null && cForcedOrgs.contains(sIssuer))
                {
                    //requestor is unknown, but was forced initially. Use
                    //sending party
                    _logger.debug("Assertion found with unknown forced issuer: " + sIssuer);
                    tmpReq = authnSessionOrganization;
                }
                else
                {
                    _logger.debug("Assertion found with unknown issuer: " + sIssuer);
                }
            }
            else
            {
                tmpReq = authnSessionOrganization;
            }
            
            //validate assertion
            if (tmpReq != null) //requestor found
            {
                if (tmpReq == authnSessionOrganization)
                {
                    //validator for assertions
                    ResponseValidator newValidator = new ResponseValidator
                        (_entityDescriptor.getEntityID(), samlResponseOrganization, 
                            _spSSODescriptor.getWantAssertionsSigned());
                    if (!newValidator.validateMessage(context, as))
                    {
                        _logger.warn("Assertion signature validation failure");
                        return UserEvent.AUTHN_METHOD_FAILED;
                    }
                }
                else
                {
                    //'Foreign' requestor, new validator necessary.
                    ResponseValidator newValidator = new ResponseValidator(
                        _entityDescriptor.getEntityID(), tmpReq, 
                        _spSSODescriptor.getWantAssertionsSigned());
                    if (!newValidator.validateMessage(context, as))
                    {
                        _logger.warn("Foreign Assertion signature validation failure");
                        return UserEvent.AUTHN_METHOD_FAILED;
                    }
                }
                
                //Everything ok, set assertion
                assertion = as;
                samlResponseOrganization = tmpReq;
                break;
            }
        }
        
        if (assertion == null)
        {
            _logger.debug("No (valid) assertions found");
            return UserEvent.AUTHN_METHOD_FAILED;
        }
        
        //DD: we don't support encrypted assertions
        List<EncryptedAssertion> encAssertions = resp.getEncryptedAssertions();
        if (encAssertions != null && !encAssertions.isEmpty())
        {
            _logger.debug("One or more encrypted assertions received and ignored. This feature is not implemented yet.");
        }
        
        String sAssertionIssuer = (assertion.getIssuer() == null ? null : assertion.getIssuer().getValue());
        if (!samlResponseOrganization.getID().equals(sAssertionIssuer))
        {
            _logger.debug("Assertion issuer not found or correct");
            return UserEvent.AUTHN_METHOD_FAILED;
        }

        Conditions conditions = assertion.getConditions();
        if (conditions != null)
        {//DD if conditions are available, then they must be evaluated (saml-core-2.0-os r569)
            if (!doConditions(conditions))
            {
                _logger.debug("Response conditions not met");
                return UserEvent.AUTHN_METHOD_FAILED;
            }
        }

        Subject subject = assertion.getSubject();
        if (subject == null)
        {
            _logger.debug("Missing required subject");
            return UserEvent.AUTHN_METHOD_FAILED;
        }
        
        IUser oAssertionUser = createUserFromAssertion(assertion, _sMethodID, samlResponseOrganization.getID());
        
        IUser oSessionUser = session.getUser();
        if (oSessionUser == null && oAssertionUser == null) {
            //No user found: error
            _logger.debug("Response user conditions not met (no user found)");
            return UserEvent.AUTHN_METHOD_FAILED;
        }
        else if (oSessionUser != null && oAssertionUser != null) {
            //verify UID
            if (!oSessionUser.getID().equals(oAssertionUser.getID())) {
                _logger.debug("Response user conditions not met (UID has changed during remote authN)");
                return UserEvent.AUTHN_METHOD_FAILED;
            }
        }
        else if (oSessionUser == null) {
            oSessionUser = oAssertionUser;
        }
  
        if (assertion.getAuthnStatements().size() < 1)
        {
            _logger.debug("No AuthN statement found");
            return UserEvent.AUTHN_METHOD_FAILED;
        }
        
        SAMLRemoteUser samlUser = null;
        if (oSessionUser instanceof SAMLRemoteUser)
            samlUser = (SAMLRemoteUser)oSessionUser;
        
        //authenticating authorities must be proxied back to the profile 
        List<String> listAuthenticatingAuthorities = new Vector<String>();
        
        for (AuthnStatement stmt : assertion.getAuthnStatements())
        {
            if (!checkAuthNStatement(stmt))
            {
                _logger.debug("Response conditions not met");
                return UserEvent.AUTHN_METHOD_FAILED;
            }
            
            //DD Session Index must first be stored in the user object instead of in the IDP alias store, because the TGT isn't available yet
            String sessionIndex = stmt.getSessionIndex();
            if (samlUser != null && sessionIndex != null)
                samlUser.addSessionIndex(sessionIndex);
            
            //DD proxy the authncontext classref back to the profile
            AuthnContext authnContext = stmt.getAuthnContext();
            if (authnContext != null)
            {
                AuthnContextClassRef classRef = authnContext.getAuthnContextClassRef();
                if (classRef != null)
                {
                    session.getAttributes().put(ProxyAttributes.class, ProxyAttributes.AUTHNCONTEXT_CLASS_REF, classRef.getAuthnContextClassRef());
                }
                
                List<AuthenticatingAuthority> listAuthorities = authnContext.getAuthenticatingAuthorities();
                if (listAuthorities != null)
                {
                    for (AuthenticatingAuthority authority: listAuthorities)
                    {
                        String sURI = authority.getURI();
                        if (sURI != null)
                            listAuthenticatingAuthorities.add(sURI);
                    }
                }
            }
        }
        
        if (!listAuthenticatingAuthorities.contains(authnSessionOrganization.getID()))
            listAuthenticatingAuthorities.add(authnSessionOrganization.getID());
        
        session.getAttributes().put(ProxyAttributes.class, 
            ProxyAttributes.AUTHNCONTEXT_AUTHENTICATING_AUTHORITIES, 
            listAuthenticatingAuthorities);
        
        //Attribute handling
        IAttributes oAttributes = null;
        IAttributes oRemoteAttributes = getAttributeMap(assertion.getAttributeStatements());
        if (oRemoteAttributes != null)
        {
            oAttributes = mapAttributes(oRemoteAttributes, oSessionUser.getAttributes(), attributeMapper);
        }
        else
            oAttributes = oSessionUser.getAttributes();
        
        oSessionUser.setAttributes(oAttributes);
                
        session.setUser(oSessionUser);
        
        //reset session so not to confuse other SAML components in the chain.
        request.setAttribute(SAML2AuthNConstants.RESPONSE_ENDPOINT_PARAM, new Boolean(false));
        
        return UserEvent.AUTHN_METHOD_SUCCESSFUL;
    }
    
    /**
     * Returns the first supported binding.
     * 
     * @param idpSSODescriptor IDP SSO Descriptor where to look for the binding.
     * @return The first SSO Service binding as String 
     */
    protected String getSupportedBinding(IDPSSODescriptor idpSSODescriptor)
    {
        if (idpSSODescriptor != null)
        {
            List<SingleSignOnService> ssoServices = idpSSODescriptor.getSingleSignOnServices();
            
            if (ssoServices.size() > 0)
            {
                return ssoServices.get(0).getBinding();
            }
        }
        else
        {
            _logger.debug("Could not determine binding, no IDP role descriptor found");
        }

        return null;
    }
    
    /**
     * Creates the SAML2 AuthnRequest object. 
     * @return SAML2 AuthnRequest object
     */
    protected AuthnRequest buildAuthnRequest()
    {
        AuthnRequestBuilder builder = (AuthnRequestBuilder)
        _builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
    
        AuthnRequest request = builder.buildObject();
        
        return request;
    }
    
    /**
     * Creates the SAML2 RequestedAuthnContext object. 
     * @param sessionAttributes Session Attributes
     * @return RequestedAuthnContext object
     */
    @SuppressWarnings("unchecked")//because of List<String> retrieval from session attributes
    protected RequestedAuthnContext buildRequestedAuthnContext(ISessionAttributes sessionAttributes)
    {
        //add optional configurable AuthnContext parameters
        List<String> listClassRefs = (List<String>)sessionAttributes.get(
            ProxyAttributes.class, ProxyAttributes.AUTHNCONTEXT_CLASS_REFS);
        if (listClassRefs == null && !_listAuthnContextClassRefs.isEmpty())
        {
            _logger.debug("Using configured ClassRefs: " + _listAuthnContextClassRefs);
            listClassRefs = new Vector<String>();
            listClassRefs.addAll(_listAuthnContextClassRefs);
        }
        
        String sComparison = 
            (String)sessionAttributes.get(
                ProxyAttributes.class, ProxyAttributes.AUTHNCONTEXT_COMPARISON_TYPE);
        if (sComparison == null && _sAuthnContextComparison != null)
        {
            _logger.debug("Using configured Comparison: " + _sAuthnContextComparison);
            sComparison = _sAuthnContextComparison;
        }
        
        RequestedAuthnContext requestedAuthnContext = null;
        if (listClassRefs != null)
        {
            _logger.debug("Using session attribute: " + ProxyAttributes.AUTHNCONTEXT_CLASS_REFS);
            RequestedAuthnContextBuilder racBuilder = 
                (RequestedAuthnContextBuilder)_builderFactory.getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
            
            requestedAuthnContext= racBuilder.buildObject();
            
            for (String classRef: listClassRefs)
            {
                AuthnContextClassRefBuilder classRefBuilder = 
                    (AuthnContextClassRefBuilder)_builderFactory.getBuilder(
                        AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
                
                AuthnContextClassRef authnContextClassRef = classRefBuilder.buildObject();
                authnContextClassRef.setAuthnContextClassRef(classRef);
                
                requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
            }
            
            if (sComparison != null)
            {
                AuthnContextComparisonTypeEnumeration comparisonType = null;
                if (sComparison.equalsIgnoreCase(AuthnContextComparisonTypeEnumeration.MINIMUM.toString()))
                    comparisonType = AuthnContextComparisonTypeEnumeration.MINIMUM;
                else if (sComparison.equalsIgnoreCase(AuthnContextComparisonTypeEnumeration.BETTER.toString()))
                    comparisonType = AuthnContextComparisonTypeEnumeration.BETTER;
                else if (sComparison.equalsIgnoreCase(AuthnContextComparisonTypeEnumeration.EXACT.toString()))
                    comparisonType = AuthnContextComparisonTypeEnumeration.EXACT;
                else if (sComparison.equalsIgnoreCase(AuthnContextComparisonTypeEnumeration.MAXIMUM.toString()))
                    comparisonType = AuthnContextComparisonTypeEnumeration.MAXIMUM;
                else
                    _logger.debug("Unknown comparison type available as session attribute: " + sComparison);
                
                if (comparisonType != null)
                {
                    _logger.debug("Using comparison type session attribute: " + ProxyAttributes.AUTHNCONTEXT_COMPARISON_TYPE);
                    requestedAuthnContext.setComparison(comparisonType);
                }
            }
        }
        
        return requestedAuthnContext;
    }
    
    private void readAuthnContextConfig(IConfigurationManager configurationManager, Element config) 
        throws OAException
    {
        _sAuthnContextComparison = configurationManager.getParam(config, "Comparison");
        if (_sAuthnContextComparison == null)
        {
            _logger.info("No optional 'Comparison' parameter in 'AuthnContext' section found in configuration");
            _sAuthnContextComparison = null;
        }
        else
        {
            _logger.info("Using configured AuthnContext Comparison value: " + _sAuthnContextComparison);
        }
        
        Element eClassRefs = configurationManager.getSection(config, "ClassRefs");
        if (eClassRefs == null)
        {
            _logger.info("No optional 'ClassRefs' section in 'AuthnContext' section found in configuration");
            _listAuthnContextClassRefs = new Vector<String>();
        }
        else
        {
            Element eClassRef = configurationManager.getSection(eClassRefs, "ClassRef");
            if (eClassRef == null)
            {
                _logger.error("No 'ClassRef' section in 'ClassRefs' section found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            while (eClassRef != null)
            {
                String sClassRefURI = configurationManager.getParam(eClassRef, "uri");
                if (sClassRefURI == null)
                {
                    _logger.error("No 'uri' parameter in 'ClassRef' section found in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (_listAuthnContextClassRefs.contains(sClassRefURI))
                {
                    _logger.error("Configured 'uri' parameter in 'ClassRef' section is not unique: " + sClassRefURI);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
                
                _listAuthnContextClassRefs.add(sClassRefURI);
                
                _logger.info("Using configured AuthnContext ClassRef uri: " + sClassRefURI);
                
                eClassRef = configurationManager.getNextSection(eClassRef);
            }
        }
    }
    
    private boolean isCompatible()
    {
        try
        {
            IAttributes.class.getDeclaredMethod("getFormat", String.class);
            return true;
        }
        catch (java.lang.SecurityException e)
        {
            //false
        }
        catch (NoSuchMethodException e)
        {
            //false
        }
        return false;
    }
}
