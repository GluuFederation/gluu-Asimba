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
package com.alfaariss.oa.profile.saml2.profile.sso;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.utility.web.URLPathContext;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004Builder;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.authentication.AuthenticationException;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;
import com.alfaariss.oa.engine.core.authentication.factory.IAuthenticationProfileFactory;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.profile.saml2.profile.sso.protocol.AuthenticationRequestProtocol;
import com.alfaariss.oa.util.ModifiedBase64;
import com.alfaariss.oa.util.logging.RequestorEventLogItem;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.saml2.NameIDFormatter;
import com.alfaariss.oa.util.saml2.SAML2Constants;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.SAML2Requestor;
import com.alfaariss.oa.util.saml2.SAML2Requestors;
import com.alfaariss.oa.util.saml2.SAML2SecurityException;
import com.alfaariss.oa.util.saml2.StatusException;
import com.alfaariss.oa.util.saml2.binding.AbstractDecodingFactory;
import com.alfaariss.oa.util.saml2.binding.AbstractEncodingFactory;
import com.alfaariss.oa.util.saml2.binding.BindingProperties;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;
import com.alfaariss.oa.util.saml2.metadata.role.sso.IDPSSODescriptorBuilder;
import com.alfaariss.oa.util.saml2.profile.AbstractSAML2Profile;
import com.alfaariss.oa.util.saml2.profile.ISAML2Profile;
import com.alfaariss.oa.util.saml2.proxy.ProxyAttributes;
import com.alfaariss.oa.util.validation.SessionValidator;

/**
 * WebBrowser SSO SAML2 Profile.
 *
 * Implementation of the SAML2 WebBrowser SSO profile.
 * @author MHO
 * @author Alfa & Ariss
 */
public class WebBrowserSSO extends AbstractSAML2Profile
{
    /** RelayState */
    public final static String SESSION_REQUEST_RELAYSTATE = "RelayState";
    
    /** NameIDPolicy */
    public final static String TGT_REQUEST_NAMEIDFORMAT = "NameIDFormat";
    /** SPNameQualifier */
    public final static String TGT_REQUEST_SPNAMEQUALIFIER = "SPNameQualifier";
    
    /** Type: sourceid */
    public final static String TYPE_SOURCEID = "sourceid";
    
    private final static int TGT_ALIAS_LENGTH = 256;
    private final static long DEFAULT_RESPONSE_EXPIRATION = 60000;
    private final static String PROPERTY_AUTHNCONTEXT = ".authncontext";
    
    private Log _logger;
    private BindingProperties _requestBindingProperties;
    private BindingProperties _responseBindingProperties;
    private Hashtable<String, String> _htAuthnContexts;
    private NameIDFormatter _nameIDFormatter;
    private String _sAttributeNameFormatDefault;
    private Hashtable<String,String> _htAttributeNameFormatMapper;
    private IDPSSODescriptor _idpSSODescriptor;
    private SecureRandom _oSecureRandom;
    private long _lExpirationOffset;
    private IAuthenticationProfileFactory _authnProfileFactory;
    private ITGTAliasStore _spAliasStore;
    private boolean _bCompatible;
    
    /**
     * Constructor. 
     */
    public WebBrowserSSO ()
    {
        _logger = LogFactory.getLog(WebBrowserSSO.class);
        _htAttributeNameFormatMapper = new Hashtable<String,String>();
    }

    /**
     * @see com.alfaariss.oa.util.saml2.profile.AbstractSAML2Profile#init(
     * com.alfaariss.oa.api.configuration.IConfigurationManager, 
     * org.w3c.dom.Element, org.opensaml.saml2.metadata.EntityDescriptor, 
     * java.lang.String, java.lang.String, 
     * com.alfaariss.oa.util.saml2.SAML2Requestors, 
     * com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow, java.lang.String)
     */
    public void init(IConfigurationManager configurationManager,
        Element config, EntityDescriptor entityDescriptor, String sBaseUrl, 
        String sWebSSOPath, SAML2Requestors requestors, 
        SAML2IssueInstantWindow issueInstantWindow, String sProfileID) throws OAException
    {
        super.init(configurationManager, config, entityDescriptor, sBaseUrl, 
            sWebSSOPath, requestors, issueInstantWindow, sProfileID);
        
        _oSecureRandom = _cryptoManager.getSecureRandom();
        
        _authnProfileFactory = Engine.getInstance().getAuthenticationProfileFactory();
        
        //read bindings config
        Element eBindings = configurationManager.getSection(config, "bindings");
        if (eBindings == null)
        {
            _logger.error(
                "No 'bindings' section found in 'profile' section in configuration with profile id: " 
                + _sID);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _requestBindingProperties = new BindingProperties(configurationManager, eBindings);
        _responseBindingProperties = new BindingProperties(configurationManager, eBindings);
        
        //read NameID config
        Element eNameID = configurationManager.getSection(config, "nameid");
        if (eNameID == null)
        {
            _logger.error(
                "No 'nameid' section found in 'profile' section in configuration with profile id: " 
                + _sID);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _spAliasStore = _tgtFactory.getAliasStoreSP();
        if (_spAliasStore == null)
        {
            _logger.error("TGT Factory has no SP Role alias support");
            throw new OAException(SystemErrors.ERROR_INIT);
        }
        
        _nameIDFormatter = new NameIDFormatter(configurationManager, eNameID, 
            _cryptoManager, _spAliasStore);
        
        if (_nameIDFormatter.getDefault() == null)
        {
            _logger.error(
                "No 'default' item found in 'nameid' section in configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _htAuthnContexts = readAuthnContextTypes(configurationManager, config);
        
        _htAttributeNameFormatMapper.clear();
        Element eResponse = configurationManager.getSection(config, "response");
        if (eResponse == null)
        {
            _logger.info(
                "No optional 'response' section found in 'profile' section in configuration with profile id: " 
                + _sID);

            _sAttributeNameFormatDefault = null;
            _lExpirationOffset = DEFAULT_RESPONSE_EXPIRATION;
        }
        else
        {
            readResponseConfig(configurationManager, eResponse);
        }
        
        //check if OA Server 1.5 is used
        _bCompatible = isCompatible();
        _logger.info("Artifact binding: " + (_bCompatible ? "supported" : "not supported"));
        _logger.info("Optional user attribute name format: " + (_bCompatible ? "supported" : "not supported"));
        _logger.info("Passive authentication: " + (_bCompatible ? "supported" : "not supported"));
        
        if (!_bCompatible && _requestBindingProperties.isSupported(SAMLConstants.SAML2_ARTIFACT_BINDING_URI))
        {
            StringBuffer sbWarn = new StringBuffer("Disabling '");
            sbWarn.append(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
            sbWarn.append("' binding as request binding, because it is not supported in this version");
            _logger.warn(sbWarn.toString());
            
            List<String> listBindings = new Vector<String>();
            listBindings.addAll(_requestBindingProperties.getBindings());
            listBindings.remove(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
            _requestBindingProperties.setBindings(listBindings);
        }
        
        updateEntityDescriptor(configurationManager, config);
    }

    /**
     * @see ISAML2Profile#process(javax.servlet.http.HttpServletRequest, 
     *  javax.servlet.http.HttpServletResponse)
     */
    public void process(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) throws OAException
    {
        ISession session = null;
        try
        {
            String sSessionId = servletRequest.getParameter(ISession.ID_NAME);
            if (sSessionId != null)
            {
                if(!SessionValidator.validateDefaultSessionId(sSessionId))
                {
                    _logger.warn("Invalid session id in request: " + sSessionId);
                    throw new UserException(UserEvent.REQUEST_INVALID);
                }
                session = _sessionFactory.retrieve(sSessionId);
                
                if (session == null)
                {
                    StringBuffer sbError = new StringBuffer("No session with id '");
                    sbError.append(sSessionId);
                    sbError.append("' found in request sent from IP: ");
                    sbError.append(servletRequest.getRemoteAddr());
                    _logger.debug(sbError.toString());
                    throw new UserException(UserEvent.REQUEST_INVALID);
                }
                
                if (session.isExpired())
                {
                    StringBuffer sbError = new StringBuffer(
                        "Expired session with id '");
                    sbError.append(sSessionId);
                    sbError.append("' found in request sent from IP: ");
                    sbError.append(servletRequest.getRemoteAddr());
                    _logger.debug(sbError.toString());
                    
                    throw new UserException(UserEvent.REQUEST_INVALID);
                }
                
                processAuthenticationResponse(servletRequest, servletResponse, 
                    session);
            }
            else
                processSAMLRequest(servletRequest, servletResponse, session);
        }
        catch(UserException e) //User error
        {            
            UserEventLogItem logItem = null;
            if(session != null)
                logItem = new UserEventLogItem(session, 
                    servletRequest.getRemoteAddr(), e.getEvent(), this, null);    
            else
                logItem = new UserEventLogItem(null, null, null, e.getEvent(), 
                    null, servletRequest.getRemoteAddr(), null, this, null);   
            _eventLogger.info(logItem);
            
            if(!servletResponse.isCommitted()) 
            {
                try
                {
                    servletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
                }
                catch (IOException e1)
                {
                    _logger.warn("Could not send response",e1);
                }             
            }  
        } 
        catch (SAML2SecurityException e)
        {
            //DD Security error -> Return a "403 Forbidden" response
            _logger.debug("Security error", e);
            
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
        catch(OAException e)
        {
            RequestorEventLogItem oLogItem = null;
            if (session != null)
                oLogItem = new RequestorEventLogItem(session, 
                servletRequest.getRemoteAddr(), RequestorEvent.REQUEST_INVALID, 
                this, null);
            else
                oLogItem = new RequestorEventLogItem(null, null, 
                    null, RequestorEvent.REQUEST_INVALID, null,
                    servletRequest.getRemoteAddr(), null, 
                    this, null);
            _eventLogger.info(oLogItem);
        
            throw e;
        }
        catch (Exception e)
        {
            RequestorEventLogItem oLogItem = null;
            if (session != null)
                oLogItem = new RequestorEventLogItem(session, 
                servletRequest.getRemoteAddr(), RequestorEvent.INTERNAL_ERROR, 
                this, null);
            else
                oLogItem = new RequestorEventLogItem(null, null, 
                    null, RequestorEvent.INTERNAL_ERROR, null,
                    servletRequest.getRemoteAddr(), null, 
                    this, null);
            _eventLogger.info(oLogItem);
            
            _logger.fatal("Internal error during process", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        } 
    }
    
    private void processSAMLRequest(HttpServletRequest request,
        HttpServletResponse response, ISession session) 
        throws OAException, SAML2SecurityException, UserException
    {
        try
        {
            AbstractDecodingFactory decFactory = 
                AbstractDecodingFactory.resolveInstance(request, 
                    response, _requestBindingProperties);
            
            if (decFactory == null)
            {
                _logger.error("No decode factory available for request");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            SAMLMessageDecoder decoder = decFactory.getDecoder();
    
            //check all supported bindings
            String sBindingURI = decoder.getBindingURI();
            if (!_requestBindingProperties.isSupported(sBindingURI))
            {
                _logger.error("The binding is not supported by this protocol: " 
                    + sBindingURI);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            _logger.debug("Binding URI: " + sBindingURI);
            
            //decode request
            SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
                context = decFactory.getContext();
            
            String sSAMLart = request.getParameter("SAMLart");
            if (sSAMLart != null)
            {
                //SAML artifact received, requestor metadata and IssuerID must be added
                //in order to enable the decoder to decode artifact
                
                byte[] bb = Base64.decode(sSAMLart);
                SAML2ArtifactType0004 b = null;
                SAML2ArtifactType0004Builder bf = new SAML2ArtifactType0004Builder();
                b = bf.buildArtifact(bb);
                
                SAML2Requestor saml2Requestor = resolveRequestor(b.getSourceID());
                if (saml2Requestor == null)
                {
                    StringBuffer sbDebug = new StringBuffer("Unknown requestor specified with with SourceID '");
                    sbDebug.append(Arrays.toString(b.getSourceID()));
                    sbDebug.append("' in artifact: ");
                    sbDebug.append(sSAMLart);
                    _logger.warn(sbDebug.toString());
                    throw new UserException(UserEvent.REQUEST_INVALID);
                }
                
                MetadataProvider oMetadataProvider = 
                    saml2Requestor.getMetadataProvider();
                if (oMetadataProvider != null)
                    context.setMetadataProvider(oMetadataProvider);
                
                context.setInboundMessageIssuer(saml2Requestor.getID());
                context.setOutboundMessageIssuer(_sEntityID);
            }
            
            try
            {
                decoder.decode(context);
            }
            catch(MessageDecodingException e)
            {
                _logger.debug("Could not decode request", e);
                throw new UserException(UserEvent.REQUEST_INVALID);
            }
            catch(SecurityException e)
            {
                _logger.debug(
                    "Could not decode inbound message due to security exception", e);
                throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
            }
            
            //verify saml message in request
            XMLObject requestMessage = context.getInboundSAMLMessage();
            
            if (_logger.isDebugEnabled())
            {
                if (requestMessage != null)
                    logXML(requestMessage);
            }
            
            if (requestMessage == null)
            {
                _logger.error("No SAML Message found in request");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            else if (requestMessage instanceof AuthnRequest)
            {
                processAuthenticationRequest(request, response, session, 
                    context, (AuthnRequest)requestMessage);
            }
            else
            {
                _logger.error("Unsupported SAML message in request");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        catch (SAML2SecurityException e)
        {
            throw e;
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not process SAML request message", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private void processAuthenticationRequest(HttpServletRequest request,
        HttpServletResponse response, ISession session, 
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
        context, AuthnRequest authnRequest) 
        throws OAException, SAML2SecurityException
    {
        AuthenticationRequestProtocol protocol = null;
        try
        {
            String sRequestorId = context.getInboundMessageIssuer();

            SAML2Requestor saml2Requestor = validateRequest(context, SPSSODescriptor.DEFAULT_ELEMENT_NAME);
            
            session = _sessionFactory.createSession(sRequestorId);
            
            String relayState = context.getRelayState();
            if (relayState != null)
            {
                ISessionAttributes attributes = session.getAttributes();
                attributes.put(WebBrowserSSO.class, 
                    SESSION_REQUEST_RELAYSTATE, relayState);
            }
            
            URLPathContext oURLPathContext = getURLPathContext(request);
            if (oURLPathContext != null)
            	session.getAttributes().put(
            			com.alfaariss.oa.util.session.ProxyAttributes.class, 
            			com.alfaariss.oa.util.session.ProxyAttributes.PROXY_URLPATH_CONTEXT, oURLPathContext);
            
            _logger.debug("Put on map? "+com.alfaariss.oa.util.session.ProxyAttributes.PROXY_URLPATH_CONTEXT+"="+oURLPathContext);
            //TODO (MHO) (Optional) Extensions support?
            
            protocol = new AuthenticationRequestProtocol(session, 
                _nameIDFormatter, _sProfileURL, _sEntityID, saml2Requestor, 
                _cryptoManager, _issueInstantWindow, _bCompatible, _bEnableProxiedEntityId);
            
            session = protocol.processRequest(authnRequest);
            
            if (!_requestBindingProperties.isSupported(protocol.getProtocolBinding()))
            {
                _logger.debug("Response binding is not supported: " 
                    + protocol.getProtocolBinding());
                throw new StatusException(RequestorEvent.REQUEST_INVALID, 
                    StatusCode.RESPONDER_URI, StatusCode.UNSUPPORTED_BINDING_URI);
            }
            
            //generate session id
            session.persist();
            
            RequestorEventLogItem oLogItem = new RequestorEventLogItem(session, 
                request.getRemoteAddr(), RequestorEvent.AUTHN_INITIATION_SUCCESSFUL, 
                this, null);
            _eventLogger.info(oLogItem);
            
            forwardUser(request, response, session);
        }
        catch (StatusException e)
        {
            //The request was invalid, so try to send a SAML error response.
            StatusResponseType samlResponse = protocol.createErrorResponse(
                protocol.getDestination(), e.getTopLevelstatusCode(), 
                e.getSecondLevelStatusCode());
            sendResponse(request, response, context, samlResponse, protocol, 
                session);
            
            RequestorEventLogItem oLogItem = new RequestorEventLogItem(session, 
                    request.getRemoteAddr(), e.getEvent(), this, null);
            _eventLogger.info(oLogItem);

            //AuthN Session can be removed
            session.expire();
            session.persist();
        }
        catch (SAML2SecurityException e)
        {
            throw e;       
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not process AuthnRequest", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private void processAuthenticationResponse(HttpServletRequest request,
        HttpServletResponse response, ISession session) throws OAException
    {
        try
        {
            String sRequestorID = session.getRequestorId();
            
            IRequestor oRequestor = 
                _requestorPoolFactory.getRequestor(sRequestorID);
            if (oRequestor == null)
            {
                _logger.debug("No OA Requestor found with id: " + sRequestorID);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            SAML2Requestor saml2Requestor = _requestors.getRequestor(oRequestor);
            
            SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
                context = createEncodingContext(request, response);
            context.setInboundMessageIssuer(sRequestorID);
            context.setOutboundMessageIssuer(_sEntityID);
            MetadataProvider oMetadataProvider = 
                saml2Requestor.getMetadataProvider();
            if (oMetadataProvider != null)
                context.setMetadataProvider(oMetadataProvider);
            
            AuthenticationRequestProtocol protocol = 
                new AuthenticationRequestProtocol(session, _nameIDFormatter, 
                    _sProfileURL, _sEntityID, saml2Requestor, _cryptoManager, 
                    _issueInstantWindow, _bCompatible, _bEnableProxiedEntityId);
            
            StatusResponseType samlResponse = null;
            RequestorEventLogItem oLogItem = null;
            switch (session.getState())
            {
                case AUTHN_OK:
                {
                    ITGT tgt = null;
                    String tgtID = session.getTGTId();
                    if (tgtID == null)
                    {
                        _logger.debug("No TGT ID found in session with id: " 
                            + session.getId());
                    }
                    else
                    {
                        tgt = _tgtFactory.retrieve(tgtID);
                        if (tgt == null)
                        {
                            _logger.debug("No TGT found with id: " + tgtID);
                            throw new OAException(SystemErrors.ERROR_INTERNAL);
                        }
                        
                        String sNameIDFormat = protocol.getNameIDFormat();
                        if (sNameIDFormat != null)
                            tgt.getAttributes().put(this.getClass(), 
                                TGT_REQUEST_NAMEIDFORMAT, sNameIDFormat);
                        
                        String sSPNameQualifier = protocol.getSPNameQualifier();
                        if (sSPNameQualifier != null)
                            tgt.getAttributes().put(this.getClass(), 
                                TGT_REQUEST_SPNAMEQUALIFIER, sSPNameQualifier);
                    }

                    List<String> listAuthnContextTypes = 
                        resolveAuthNContextTypes(session, tgt);
                    
                    String sTGTAlias = resolveTGTAlias(tgtID, sRequestorID);
                    
                    List<String> listAuthenticatingAuthorities = 
                        resolveAuthNContextAuthenticatingAuthorities(session, tgt);
                    
                    samlResponse = protocol.createResponse(tgt, 
                        listAuthnContextTypes, session.getUser().getAttributes(), 
                        _sAttributeNameFormatDefault, 
                        _htAttributeNameFormatMapper, sTGTAlias, 
                        _lExpirationOffset, listAuthenticatingAuthorities);
                    
                    if (samlResponse == null)
                    {//DD Because the SAML response creation went wrong, authn failed for the user; So the requestor must be logged out and if no requestor is using the TGT anymore, it (the TGT) must be removed.
                        if (tgt != null)
                        {
                            tgt.removeRequestorID(sRequestorID);
                            _spAliasStore.removeAlias(NameIDFormatter.TYPE_ALIAS_TGT, sRequestorID, sTGTAlias);
                            
                            if (tgt.getRequestorIDs().size() == 0)
                                tgt.expire();
                        }
                        
                        samlResponse = protocol.createErrorResponse(
                            protocol.getDestination(), StatusCode.RESPONDER_URI, 
                            null);
                    }
                    
                    if (tgt != null)
                    {//update with new attributes of perform remove after expire
                        tgt.persist();
                    }
                    
                    //TODO (MHO) New RequestorEvent should be logged.
                    oLogItem = new RequestorEventLogItem(session, 
                        request.getRemoteAddr(), 
                        RequestorEvent.TOKEN_DEREFERENCE_SUCCESSFUL, 
                        this, null);
                    
                    break;
                }
                case PASSIVE_FAILED:
                {
                    samlResponse = protocol.createErrorResponse(
                        protocol.getDestination(), StatusCode.RESPONDER_URI, 
                        StatusCode.NO_PASSIVE_URI);
                    break;
                }
                case USER_CANCELLED:
                case AUTHN_FAILED:
                case PRE_AUTHZ_FAILED:
                case POST_AUTHZ_FAILED:
                case AUTHN_SELECTION_FAILED:
                case USER_BLOCKED:
                case USER_UNKNOWN:
                default:
                {
                    samlResponse = protocol.createErrorResponse(
                        protocol.getDestination(), StatusCode.RESPONDER_URI, 
                        StatusCode.AUTHN_FAILED_URI);
                    break;
                }
            }
            
            sendResponse(request, response, context, samlResponse, protocol, 
                session);
            
            if (oLogItem == null)
                oLogItem = new RequestorEventLogItem(session, 
                    request.getRemoteAddr(), 
                    RequestorEvent.TOKEN_DEREFERENCE_FAILED, 
                    this, null);
            
            _eventLogger.info(oLogItem);

            //AuthN Session can be removed
            session.expire();
            session.persist();
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not generate an authentication response", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    private void sendResponse(HttpServletRequest request,
        HttpServletResponse response, 
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> context, 
        StatusResponseType samlResponse, AuthenticationRequestProtocol protocol, 
        ISession session) 
        throws OAException
    {
        try
        {
            ISessionAttributes attributes = session.getAttributes();
            if (attributes.contains(
                WebBrowserSSO.class, SESSION_REQUEST_RELAYSTATE))
            {
                String relayState = (String)attributes.get(WebBrowserSSO.class, 
                    SESSION_REQUEST_RELAYSTATE); 
                context.setRelayState(relayState);
            }
            
            if (_signingEnabled)
            {
                Credential credentials = SAML2CryptoUtils.retrieveMySigningCredentials(
                    _cryptoManager, _sEntityID);  
                context.setOutboundSAMLMessageSigningCredential(credentials);
            }
            
            context.setOutboundSAMLMessage(samlResponse);
            context.setLocalEntityId(_sEntityID);
            
            //resolve response binding
            String sBindingType = protocol.getProtocolBinding();
            if (sBindingType == null || !_responseBindingProperties.isSupported(sBindingType))
            {
                _logger.debug("Using default binding: " + _responseBindingProperties.getDefault());
                sBindingType = _responseBindingProperties.getDefault();
            }
            
            //Add my metadata
            context.setLocalEntityMetadata(_entityDescriptor);
            context.setLocalEntityRoleMetadata(_idpSSODescriptor);
            
            String sDestination = samlResponse.getDestination();
            if (sDestination == null)
            {
                _logger.warn("No destination for response available");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            Endpoint endPoint = buildMetadataEndpoint(
                SingleSignOnService.DEFAULT_ELEMENT_NAME, sBindingType, 
                sDestination, null);
            context.setPeerEntityEndpoint(endPoint);
                        
            AbstractEncodingFactory encFactory = 
                AbstractEncodingFactory.createInstance(request, response, 
                    sBindingType, _responseBindingProperties);
            
            SAMLMessageEncoder encoder = encFactory.getEncoder();
            
            encoder.encode(context);
            
            if (_logger.isDebugEnabled())
            {
                XMLObject xmlObject = context.getOutboundSAMLMessage();
                if (xmlObject != null)
                    logXML(xmlObject);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not generate response", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private void updateEntityDescriptor(
        IConfigurationManager configurationManager, Element config)
        throws OAException
    {
        _idpSSODescriptor = 
            _entityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
        if (_idpSSODescriptor == null)
            throw new IllegalArgumentException("No IDPSSODescriptor available");
        
        IDPSSODescriptorBuilder builder = new IDPSSODescriptorBuilder(
            configurationManager, config, _idpSSODescriptor);
        
        builder.buildNameIDFormats();
        builder.buildWantAuthnRequestsSigned(_requestors.isDefaultSigningEnabled());
        builder.buildSingleSignOnService(_sProfileURL, _requestBindingProperties);
    }

    private Hashtable<String, String> readAuthnContextTypes(
        IConfigurationManager configurationManager, Element config) 
        throws OAException
    {
        Hashtable<String, String> htAuthnContexts = new Hashtable<String, String>();
        
        try
        {
            Element eProfile = null;
            
            Element eAuthentication = configurationManager.getSection(
                config, "authentication");
            if (eAuthentication == null)
            {
                StringBuffer sbInfo = new StringBuffer(
                    "No optional 'authentication' section found in 'profile' section in configuration with profile id '");
                sbInfo.append(_sID);
                sbInfo.append("', using default AuthnContext: ");
                sbInfo.append(AuthnContext.UNSPECIFIED_AUTHN_CTX);
                _logger.info(sbInfo.toString());
            }
            else
            {
                eProfile = configurationManager.getSection(eAuthentication, 
                    "profile");
                if (eProfile == null)
                {
                    _logger.info(
                        "Not one 'profile' section found in 'authentication' section in configuration, using default AuthnContext: " 
                        + AuthnContext.UNSPECIFIED_AUTHN_CTX);
                }
            }
            
            while (eProfile != null)
            {
                String id = configurationManager.getParam(eProfile, "id");
                if (id == null)
                {
                    _logger.error(
                        "No 'id' item found in 'profile' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                String authnContext = configurationManager.getParam(
                    eProfile, "authncontext");
                if (authnContext == null)
                {
                    _logger.error(
                        "No 'authncontext' item found in 'profile' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (htAuthnContexts.containsKey(id))
                {
                    _logger.error(
                        "Configured 'id' item in 'profile' section is not unique: " + id);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                htAuthnContexts.put(id, authnContext);
                
                eProfile = configurationManager.getNextSection(eProfile);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not read AuthnContext types", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return htAuthnContexts;
    }
    
    private String resolveTGTAlias(String sTGTID, String sRequestorID) 
        throws OAException
    {
        String sAlias = null;
        try
        {
            do
            {
                byte[] baRandom = new byte[TGT_ALIAS_LENGTH];
                _oSecureRandom.nextBytes(baRandom);
                sAlias = new String(ModifiedBase64.encode(baRandom, 
                    SAML2Constants.CHARSET));
                //always start with underscore
                sAlias = "_" + sAlias;
            }
            while(_spAliasStore.isAlias(NameIDFormatter.TYPE_ALIAS_TGT, 
                sRequestorID, sAlias));
            
            if (sTGTID != null)
            {
                _spAliasStore.putAlias(NameIDFormatter.TYPE_ALIAS_TGT, sRequestorID, 
                    sTGTID, sAlias);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer(
                "Could not resolve TGT alias for tgt '");
            
            if (sTGTID != null)
                sbError.append(sTGTID);
            
            sbError.append("' and requestor ID: ");
            sbError.append(sRequestorID);
            _logger.fatal(sbError.toString(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return sAlias;
    }
        
    private List<String> resolveAuthNContextTypes(ISession session, ITGT tgt) 
        throws OAException
    {
        List<String> listContextTypes = new Vector<String>();
    
        if (tgt != null)
        {//first retrieve the authn context class ref available in the tgt
            String sAuthnContextClassRef = (String)tgt.getAttributes().get(ProxyAttributes.class, ProxyAttributes.AUTHNCONTEXT_CLASS_REF);
            if (sAuthnContextClassRef != null)
            {
                if (!listContextTypes.contains(sAuthnContextClassRef))
                    listContextTypes.add(sAuthnContextClassRef);
            }
        }
        
        String sAuthnContextClassRef = (String)session.getAttributes().get(ProxyAttributes.class, ProxyAttributes.AUTHNCONTEXT_CLASS_REF);
        if (sAuthnContextClassRef != null)
        {//if a class ref is available in the session, it should be stored in the tgt also
            if (!listContextTypes.contains(sAuthnContextClassRef))
            {
                listContextTypes.add(sAuthnContextClassRef);
                if (tgt != null)
                {
                    _logger.debug("Copy the proxied AuthnContextClassRef to a TGT attribute: " + sAuthnContextClassRef);
                    tgt.getAttributes().put(ProxyAttributes.class, ProxyAttributes.AUTHNCONTEXT_CLASS_REF, sAuthnContextClassRef);
                }
            }
        }
        
        List<String> listProfiles = null;
        if (tgt != null)
        {
            listProfiles = tgt.getAuthNProfileIDs();
        }
        else
        {
            listProfiles = new Vector<String>();
            IAuthenticationProfile selectedAuthNProfile = session.getSelectedAuthNProfile();
            if (selectedAuthNProfile != null)
                listProfiles.add(selectedAuthNProfile.getID());
        }
        
        for (String sAuthNProfile: listProfiles)
        {
            if (_htAuthnContexts.containsKey(sAuthNProfile))
            {
                String sAuthnContextType = _htAuthnContexts.get(sAuthNProfile);
                if (!listContextTypes.contains(sAuthnContextType))
                    listContextTypes.add(sAuthnContextType);
            }
            else
            {
                AuthenticationProfile authnProfile = null;
                try
                {
                    authnProfile = _authnProfileFactory.getProfile(sAuthNProfile);
                }
                catch (AuthenticationException e)
                {
                    _logger.error("Authentication profile not available: " + sAuthNProfile);
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                String sAuthnContextType = (String)authnProfile.getProperty(
                    _sOAProfileID + PROPERTY_AUTHNCONTEXT);
                if (sAuthnContextType != null)
                {
                    if (!listContextTypes.contains(sAuthnContextType))
                        listContextTypes.add(sAuthnContextType);
                }
            }
        }

        if (listContextTypes.isEmpty())
            listContextTypes.add(AuthnContext.UNSPECIFIED_AUTHN_CTX);
        
        return listContextTypes;
    }
    
    @SuppressWarnings("unchecked") // because of attribute casting
    private List<String> resolveAuthNContextAuthenticatingAuthorities(
        ISession session, ITGT tgt)// throws OAException
    {
        List<String> listAuthenticatingAuthorities = new Vector<String>();
        if (tgt != null)
        {//first retrieve the authn authorities that are available in the tgt
            List<String> listTGTAuthNAuthorities = (List<String>)tgt.getAttributes().get(ProxyAttributes.class, ProxyAttributes.AUTHNCONTEXT_AUTHENTICATING_AUTHORITIES);
            if (listTGTAuthNAuthorities != null)
            {
                listAuthenticatingAuthorities.addAll(listTGTAuthNAuthorities);
            }
        }
        
        List<String> listSessionAuthNAuthorities = (List<String>)session.getAttributes().get(ProxyAttributes.class, ProxyAttributes.AUTHNCONTEXT_AUTHENTICATING_AUTHORITIES);
        if (listSessionAuthNAuthorities != null)
        {//if authn authorities are available in the session, it should be stored in the tgt also
            for (String sAuthNAuthority: listSessionAuthNAuthorities)
            {
                if (!listAuthenticatingAuthorities.contains(sAuthNAuthority))
                {
                    listAuthenticatingAuthorities.add(sAuthNAuthority);
                }
            }
            
            if (tgt != null)
            {
                _logger.debug("Copy the proxied AuthenticatingAuthorities to a TGT attribute: " + listAuthenticatingAuthorities);
                tgt.getAttributes().put(ProxyAttributes.class, ProxyAttributes.AUTHNCONTEXT_AUTHENTICATING_AUTHORITIES, listAuthenticatingAuthorities);
            }
        }

        return listAuthenticatingAuthorities;
    }
    
    
    private SAML2Requestor resolveRequestor(byte[] sourceid) 
        throws OAException, UserException
    {
        IRequestor requestor = null;
        
        if (_requestorPoolFactory.isRequestorIDSupported(TYPE_SOURCEID))
        {
            requestor = _requestorPoolFactory.getRequestor(sourceid, "sourceid");
        }
        else
        {
            for (IRequestor oRequestor: _requestorPoolFactory.getAllEnabledRequestors())
            {
                byte[] baSourceID = generateSHA1(oRequestor.getID());
                if (Arrays.equals(sourceid, baSourceID))
                {
                    requestor = oRequestor;
                    break;
                }
            }
        }
        
        if (requestor == null)
        {
            _logger.debug("Unknown requestor specified with SourceID: " + Arrays.toString(sourceid));
            throw new UserException(UserEvent.REQUEST_INVALID);
        }
        
        if (!requestor.isEnabled())
        {
            _logger.debug("Disabled requestor found in request: " 
                + requestor.getID());
            throw new UserException(UserEvent.REQUEST_INVALID); 
        }
        
        RequestorPool oRequestorPool = 
            _requestorPoolFactory.getRequestorPool(requestor.getID());
        if (oRequestorPool == null)
        {
            _logger.warn("Requestor not available in a pool: " 
                + requestor.getID());
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    
        if (!oRequestorPool.isEnabled())
        {
            StringBuffer sbError = new StringBuffer("Requestor '");
            sbError.append(requestor.getID());
            sbError.append("' is found in a disabled requestor pool: ");
            sbError.append(oRequestorPool.getID());
            _logger.warn(sbError.toString());
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return _requestors.getRequestor(requestor);
    }
    
    private byte[] generateSHA1(String id) throws OAException
    {
        try
        {
            MessageDigest dig = MessageDigest.getInstance("SHA-1");
            return dig.digest(id.getBytes("UTF-8"));
        }
        catch (NoSuchAlgorithmException e)
        {
            _logger.error("SHA-1 not supported", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (UnsupportedEncodingException e)
        {
            _logger.error("UTF-8 not supported", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private void readResponseConfig(IConfigurationManager configurationManager,
        Element config) throws OAException
    {
        Element eAttributes = configurationManager.getSection(
            config, "attributes");
        if (eAttributes == null)
            _sAttributeNameFormatDefault = null;
        else
        {
            _sAttributeNameFormatDefault = configurationManager.getParam(
                eAttributes, "format");
            if (_sAttributeNameFormatDefault == null)
            {
                _sAttributeNameFormatDefault = configurationManager.getParam(
                    eAttributes, "nameformat");
                if (_sAttributeNameFormatDefault == null)
                {
                    _logger.info(
                        "No optional 'format' or 'nameformat' item in 'attributes' section found in configuration");
                }
            }
            
            Element eAttribute = configurationManager.getSection(
                eAttributes, "attribute");
            while (eAttribute != null)
            {
                String sName = configurationManager.getParam(eAttribute, "name");
                if (sName == null)
                {
                    _logger.error("No 'name' item in 'attribute' section found in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                String sFormat = configurationManager.getParam(eAttribute, "format");
                if (sFormat == null)
                {
                    _logger.error("No 'format' item in 'attribute' section found in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                if (_htAttributeNameFormatMapper.containsKey(sName))
                {
                    _logger.error("Configured 'name' in 'attribute' section is not unique: " + sName);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
                _htAttributeNameFormatMapper.put(sName, sFormat);
                
                eAttribute = configurationManager.getNextSection(eAttribute);
            }
        } 
        
        if (_sAttributeNameFormatDefault != null)
            _logger.info("Using optional attribute name format: " 
                + _sAttributeNameFormatDefault);
        else
            _logger.info("Not using optional attribute name format");
        
        Element eExpiration = configurationManager.getSection(
            config, "expiration");
        if (eExpiration == null)
            _lExpirationOffset = DEFAULT_RESPONSE_EXPIRATION;
        else
        {
            String sOffset = configurationManager.getParam(
                eExpiration, "offset");
            if (sOffset == null)
            {
                _logger.error(
                    "No 'offset' section found in 'expiration' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                _lExpirationOffset = Long.parseLong(sOffset);
                _lExpirationOffset = _lExpirationOffset * 1000;//in seconds
            }
            catch (NumberFormatException e)
            {
                _logger.error(
                    "Invalid 'offset' section found in 'expiration' section in configuration: " 
                    + _lExpirationOffset, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            if (_lExpirationOffset < 0)
            {
                _logger.error(
                    "Invalid 'offset' section found in 'expiration' section in configuration (may not be negative): " 
                    + _lExpirationOffset);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        
        _logger.info("Using expiration offset in response of (ms): " 
            + _lExpirationOffset);
    }
    
    
    private boolean isCompatible()
    {
        try
        {
            IRequestorPoolFactory.class.getDeclaredMethod("isRequestorIDSupported", String.class);
            IAttributes.class.getDeclaredMethod("getFormat", String.class);
            ISession.class.getDeclaredMethod("isPassive");
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
    
    /**
     * Establish an URLPathContext from the last part of the URL<br/>
     * i.e.<br/>
     * http://server/asimba/something-something/context=abcd;123<br/>
     * would return an URLPathContext with key:context=abcd and key:123 with null-value
     * @param oRequest HttpServletRequest to investigate
     * @return An initialized URLPathContext instance, or null when no path was present in the request 
     */
    protected URLPathContext getURLPathContext(HttpServletRequest oRequest) {
    	String sPath = oRequest.getRequestURI();
    	
    	int last = sPath.lastIndexOf("/"); 
    	if (last == -1) {
    		return null;
    	}
    	
    	return URLPathContext.fromValue(sPath.substring(last+1));
    }
}