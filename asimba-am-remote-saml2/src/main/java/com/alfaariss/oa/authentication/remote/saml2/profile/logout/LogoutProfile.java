/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.saml2.profile.logout;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.assertion.SAML2TimestampWindow;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.impl.BodyBuilder;
import org.opensaml.ws.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.idmapper.IIDMapper;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.authentication.remote.saml2.SAML2AuthNConstants;
import com.alfaariss.oa.authentication.remote.saml2.beans.SAMLRemoteUser;
import com.alfaariss.oa.authentication.remote.saml2.profile.AbstractAuthNMethodSAML2Profile;
import com.alfaariss.oa.authentication.remote.saml2.util.ResponseValidator;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;
import com.alfaariss.oa.util.saml2.SAML2ConditionsWindow;
import com.alfaariss.oa.util.saml2.SAML2Exchange;
import com.alfaariss.oa.util.saml2.binding.AbstractEncodingFactory;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;

/**
 * Performs logout requests.
 * <br>
 * Synchronous and asynchronous logout requests are supported.
 *
 * @author MHO
 * @author jre
 * @author Alfa & Ariss
 * @since 1.0
 */
public class LogoutProfile extends AbstractAuthNMethodSAML2Profile
{
    /** already loggedout at this organization */
    public final static String TGT_LOGOUT_ORGANIZATION = "aslogout_organization";//contains a ASelectOrganization object
    /** logout is in progress at this organization */
    public final static String SESSION_LOGOUT_ORGANIZATION = "aslogout_organization";//contains a ASelectOrganization object
    
    private static Log _logger;
    private String _sBinding;
    private BasicParserPool _parserPool;
    
    /**
     * Default constructor. 
     * 
     * Specify if this profile is used for synchronous or asynchronous logout 
     * by supplying one of the following bindings:
     * <ul>
     * <li>SAMLConstants.SAML2_SOAP11_BINDING_URI (synchronous)</li>
     * <li>SAMLConstants.SAML2_REDIRECT_BINDING_URI (asynchronous)</li>
     * </ul>
     * 
     * @param sBinding The supported binding for this profile.
     */
    public LogoutProfile(String sBinding)
    {
        _logger = LogFactory.getLog(LogoutProfile.class);
        _sBinding = sBinding;
        
        _parserPool = new BasicParserPool();
        _parserPool.setNamespaceAware(true);
    }
    
    /**
     * Initializes the Logout Profile.
     * 
     * @param entityDescriptor The entity descriptor.
     * @param mapper The optional user id mapper.
     * @param store The remote organization (IDP) storage.
     * @param sMethodID The authentication method ID which uses this logout profile.
     * @param conditionsWindow SAML2 Conditions Window
     * @throws OAException If initialization fails.
     * @since 1.4
     */
    public void init(EntityDescriptor entityDescriptor, IIDMapper mapper, 
        IIDPStorage store, String sMethodID, 
        SAML2ConditionsWindow conditionsWindow)
        throws OAException
    {
    	SAML2TimestampWindow oAuthnInstant = null; // this is not used in logout profile
    	
        super.init(null, null, entityDescriptor, mapper, store, sMethodID, conditionsWindow, oAuthnInstant, null);
    }
    
    /**
     * Returns the logout service of the supplied remote organization.
     * @param organization The remote organization
     * @return SingleLogoutService the service
     */
    public SingleLogoutService getService(SAML2IDP organization)
    {   
        IDPSSODescriptor idpSSODescriptor = getIDPSSODescriptor(organization);
        if (idpSSODescriptor != null)
            return getSingleLogoutService(idpSSODescriptor);
        
        return null;
    }
    
    /**
     * Performs asynchronous logout.
     * <br>
     * Supports sending the logout to the remote organization (IdP) and 
     * verifying the response. 
     * @param request Servlet request
     * @param response Servlet response
     * @param session Logout session
     * @param organization The remote organization were the user must be loggedout.
     * @param reason The reason to be used during logout or null
     * @param sSessionIndex The session index that must be loggedout
     * @return UserEvent with the logout result
     * @throws OAException If logout fails.
     */
    @SuppressWarnings("unchecked") //for SAMLMessageContext attribute
    public UserEvent processASynchronous(HttpServletRequest request,
        HttpServletResponse response, ISession session, 
        SAML2IDP organization, String reason, String sSessionIndex)
        throws OAException
    {
        if (organization == null)
        {
            _logger.warn("No organization available");
            return UserEvent.USER_LOGOUT_FAILED;
        }
        
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> context = 
            (SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject>)
            request.getAttribute(SAML2AuthNConstants.SESSION_ATTRIBUTE_NAME);
        
        if (context == null)
        {
            if (reason == null)
                reason = LogoutResponse.USER_LOGOUT_URI;
            
            return processRequest(request, response, session, organization,
                reason, sSessionIndex);
        }
        
        
        IUser user = session.getUser();
        String sOrganization = user.getOrganization();
        if (user instanceof SAMLRemoteUser)
        {
            sOrganization = ((SAMLRemoteUser)user).getIDP();
        }
        
        if (!organization.getID().equals(sOrganization))
        {
            StringBuffer sbDebug = new StringBuffer("Session invalid; User was logging out at '");
            sbDebug.append(organization.getID());
            sbDebug.append("' instead of: ");
            sbDebug.append(sOrganization);
            _logger.debug(sbDebug.toString());
            return UserEvent.USER_LOGOUT_FAILED;
        }
        
        return processResponse(context, organization);
    }
    
    /**
     * Performs asynchronous logout.
     * <br>
     * Uses the SAMLConstants.SAML2_SOAP11_BINDING_URI to logout.
     * 
     * @param user The user to be loggedout. 
     * @param organization The remote organization were to logout.
     * @param reason The optional reason (can be null)
     * @param sSessionIndex The session index that must be loggedout
     * @return UserEvent The result of the logout.
     */
    public UserEvent processSynchronous(IUser user, SAML2IDP organization, 
        String reason, String sSessionIndex)
    {
        try
        {       
            if (organization == null)
            {
                _logger.warn("No organization available");
                return UserEvent.USER_LOGOUT_FAILED;
            }
            
            IDPSSODescriptor idpSSODescriptor = getIDPSSODescriptor(organization);
            if (idpSSODescriptor == null)
            {
                _logger.debug("No IDP SSO Descriptor found for organization");
                return UserEvent.USER_LOGOUT_FAILED;
            }
            
            SingleLogoutService slService = getSingleLogoutService(idpSSODescriptor);
            if (slService != null)
            {
                SecureRandomIdentifierGenerator idgen = null;
                try
                {
                    idgen = new SecureRandomIdentifierGenerator();
                }
                catch (NoSuchAlgorithmException e)
                {
                    String msg = "Could not generate ID for logout request";
                    _logger.error(msg);
                    throw new MessageEncodingException(msg, e);
                }
                
                LogoutRequest logoutRequest = 
                    buildLogoutRequest(idgen.generateIdentifier(), user, reason, 
                        null, sSessionIndex);
                
                String location = slService.getLocation();
                
                _logger.debug("Sending synchronous logout request to location: " + location);
                
                StatusResponseType logoutResponse = (StatusResponseType)sendSOAPMessage(location, logoutRequest);
                SAMLMessageContext<SignableSAMLObject,SignableSAMLObject,SAMLObject> 
                    samlContext = new BasicSAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject>();
                samlContext.setInboundSAMLMessage(logoutResponse);
                samlContext.setInboundMessageIssuer(organization.getID());
                
                return processResponse(samlContext, organization);
            }
        }
        catch(OAException e)
        {
            _logger.debug("Creation of Logout request failed", e);
            return UserEvent.USER_LOGOUT_FAILED;
        }
        catch (ClassCastException cce)
        {
            _logger.debug("Illegally typed object retrieved from logout response", cce);
            return UserEvent.USER_LOGOUT_FAILED;
        }
        catch (SecurityException e)
        {
            _logger.debug("Signing of Logout request failed", e);
            return UserEvent.USER_LOGOUT_FAILED;
        }
        catch (MessageEncodingException e)
        {
            _logger.debug("Encoding of Logout request failed", e);
            return UserEvent.USER_LOGOUT_FAILED;
        }
        
        return UserEvent.USER_LOGOUT_FAILED;
    }
    
    private XMLObject sendSOAPMessage(String sTarget, XMLObject request) 
        throws SecurityException, MessageEncodingException
    {   
        XMLObjectBuilderFactory bf = Configuration.getBuilderFactory();
        
        BodyBuilder bodybuilder = (BodyBuilder)bf.getBuilder(Body.DEFAULT_ELEMENT_NAME);
        Body body = bodybuilder.buildObject();
        body.getUnknownXMLObjects().add(request);
        
        EnvelopeBuilder envelopeBuilder = (EnvelopeBuilder)bf.getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
        Envelope envelope = envelopeBuilder.buildObject();
        envelope.setBody(body);
        
        BasicSOAPMessageContext soapContext = new BasicSOAPMessageContext();
        soapContext.setOutboundMessage(envelope);
        
        HttpClientBuilder clientBuilder = new HttpClientBuilder();
        clientBuilder.setConnectionTimeout(5000);
        
        HttpSOAPClient soapClient = new HttpSOAPClient(
            clientBuilder.buildClient(), _parserPool);
        
        if (_logger.isDebugEnabled())
            logXML(soapContext.getOutboundMessage());
        
        try
        {
            soapClient.send(sTarget, soapContext);
        }
        catch (SOAPException e)
        {
            _logger.warn("Could not process soap message while communitating with: " + sTarget, e);
            throw new MessageEncodingException("Could not process SOAP message");
        }
        
        if (_logger.isDebugEnabled())
            logXML(soapContext.getInboundMessage());
        
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
        
        return samlResponseMessage;
    }
    
    private UserEvent processRequest(HttpServletRequest request,
        HttpServletResponse response, ISession session,
        SAML2IDP organization, String reason, String sSessionIndex)
        throws OAException
    {
        try
        {
            IDPSSODescriptor idpSSODescriptor = getIDPSSODescriptor(organization);
            if (idpSSODescriptor == null)
            {
                _logger.debug("No IDP SSO Descriptor found for organization");
                return UserEvent.USER_LOGOUT_FAILED;
            }
            
            SingleLogoutService slService = getSingleLogoutService(idpSSODescriptor);
            if (slService != null)
            {
                String requestID = generateRequestID(session.getId(), 
                    session.getAttributes());
                
                LogoutRequest logoutRequest = buildLogoutRequest(
                    requestID, session.getUser(), reason, 
                    slService.getLocation(), sSessionIndex);
                
                SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
                    context = createEncodingContext(request, response);
    
                context.setInboundMessageIssuer(organization.getID());
                context.setOutboundMessageIssuer(_entityDescriptor.getEntityID());
                context.setLocalEntityId(_entityDescriptor.getEntityID());
                context.setLocalEntityMetadata(_entityDescriptor);
                context.setLocalEntityRoleMetadata(_entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS));
                context.setMetadataProvider(organization.getMetadataProvider());

                context.setOutboundSAMLMessage(logoutRequest);
                
                Endpoint endPoint = buildMetadataEndpoint(
                    AssertionConsumerService.DEFAULT_ELEMENT_NAME, slService.getBinding(), 
                    slService.getLocation(), null);
                context.setPeerEntityEndpoint(endPoint);
                
                if (_signingEnabled)
                {
                    Credential credentials = SAML2CryptoUtils.retrieveMySigningCredentials(
                        _crypto, _entityDescriptor.getEntityID());  
                    context.setOutboundSAMLMessageSigningCredential(credentials);
                }
                
                AbstractEncodingFactory encFactory = 
                    AbstractEncodingFactory.createInstance(
                        request, response, slService.getBinding(),
                        SAML2Exchange.getSPSSOBindingProperties());
                
                if (encFactory == null)
                {
                    _logger.error("No encoding factory available for request");
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
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
                
                return UserEvent.USER_LOGOUT_IN_PROGRESS;
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.debug("Could not send logout request", e);
        }
        
        return UserEvent.USER_LOGOUT_FAILED;
    }

    private UserEvent processResponse(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context, SAML2IDP organization)
        throws OAException
    {
        try
        {   
            StatusResponseType resp = (StatusResponseType)context.getInboundSAMLMessage();
            
            //Initialize validator for responses
            //LogoutResponses require signing?
            ResponseValidator validator  = new ResponseValidator
                (_entityDescriptor.getEntityID(), organization,
                 false);
            
            validator.validateResponse(context);
            
            String sOrgID = context.getInboundMessageIssuer();
            if (!organization.getID().equals(sOrgID))
            {
                _logger.debug("Response issuer not equal to query issuer");
                return UserEvent.USER_LOGOUT_FAILED;
            }
            
            Status status = resp.getStatus();
            if (status == null)
            {
                _logger.debug("No status code available");
                return UserEvent.USER_LOGOUT_FAILED;
            }
            
            StatusCode topLevel = status.getStatusCode();
            if (topLevel == null)
            {
                _logger.debug("No required top level status code available");
                return UserEvent.USER_LOGOUT_FAILED;
            }
            
            String sTopLevel = topLevel.getValue();
            if (sTopLevel == null)
            {
                _logger.debug("No required top level status code available");
                
                return UserEvent.USER_LOGOUT_FAILED;
            }
            
            if (!StatusCode.SUCCESS_URI.equals(sTopLevel))
            {
                _logger.debug("Top level status code: " + sTopLevel);
                return UserEvent.USER_LOGOUT_FAILED;
            }
            
            StatusCode secondLevel = topLevel.getStatusCode();
            if (secondLevel != null)
            {
                String sSecondLevel = secondLevel.getValue();
                if (sSecondLevel != null)
                {
                    if (StatusCode.PARTIAL_LOGOUT_URI.equals(sSecondLevel))
                    {
                        return UserEvent.USER_LOGOUT_PARTIALLY;
                    }
                }
            }
    
            return UserEvent.USER_LOGGED_OUT;
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error when processing logout response", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    private IDPSSODescriptor getIDPSSODescriptor(SAML2IDP organization)
    {
        MetadataProvider metadataProvider;
        try
        {
            metadataProvider = organization.getMetadataProvider();
            if (metadataProvider != null)
            {
                IDPSSODescriptor idpSSODescriptor = 
                    (IDPSSODescriptor)metadataProvider.getRole(
                        organization.getID(), 
                        IDPSSODescriptor.DEFAULT_ELEMENT_NAME, 
                        SAMLConstants.SAML20P_NS);
                
                return idpSSODescriptor;
            }
        }
        catch (OAException e)
        {
            //no MetadataProvider
        }
        catch (MetadataProviderException e)
        {
            //no IDPSSODescriptor
        }
        
        return null;
    }
    
    private SingleLogoutService getSingleLogoutService(IDPSSODescriptor idpSSODescriptor)
    {
        List<SingleLogoutService> sloServices = idpSSODescriptor.getSingleLogoutServices();
        
        if (sloServices.size() > 0)
        {
            for (SingleLogoutService service : sloServices)
            {
                if (service.getBinding().equals(_sBinding))
                {
                    return service;
                }
            }
        }
        
        return null;
    }
    
    /*
     * Currently only one session index is supported.
     */
    private LogoutRequest buildLogoutRequest(String sID, IUser user, 
        String reason, String sDestination, String sSessionIndex) 
        throws OAException
    {
        LogoutRequestBuilder lrBuilder = 
            (LogoutRequestBuilder)_builderFactory.getBuilder(
                LogoutRequest.DEFAULT_ELEMENT_NAME);
        
        LogoutRequest logoutRequest = lrBuilder.buildObject();
        
        logoutRequest.setID(sID);
        
        String sNameIDFormat = null;
        String sNameQualifier = null;
        
        if (user instanceof SAMLRemoteUser)
        {
            SAMLRemoteUser userSAML = (SAMLRemoteUser)user;
            sNameIDFormat = userSAML.getFormat();
            
            //add session index to request
            SessionIndexBuilder sessionIndexBuilder = 
                (SessionIndexBuilder)_builderFactory.getBuilder(
                    SessionIndex.DEFAULT_ELEMENT_NAME);
            SessionIndex sessionIndex = sessionIndexBuilder.buildObject();
            sessionIndex.setSessionIndex(sSessionIndex);
            logoutRequest.getSessionIndexes().add(sessionIndex);
            
            //the namequalifier that was returned by the remote SAML 
            //organization is set as the organization of the remote 
            //SAML user; this way the organization is set as name qualifier
            sNameQualifier = userSAML.getOrganization();
        }
        else
            sNameQualifier = _entityDescriptor.getEntityID();
        
        NameID nid = buildNameID(user.getID(), sNameIDFormat, 
            sNameQualifier);
        logoutRequest.setNameID(nid);
        
        if (reason != null)
        {
            logoutRequest.setReason(reason);
        }
        
        logoutRequest.setVersion(SAMLVersion.VERSION_20);
        logoutRequest.setIssueInstant(new DateTime());
        logoutRequest.setIssuer(buildIssuer());
        if (sDestination != null)
            logoutRequest.setDestination(sDestination);
        
        if (_signingEnabled)
        {
            signSAMLObject(logoutRequest);
        }
        
        return logoutRequest;
    }

}
