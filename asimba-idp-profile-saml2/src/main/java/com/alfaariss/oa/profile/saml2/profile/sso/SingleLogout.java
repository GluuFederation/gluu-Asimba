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
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.DatatypeHelper;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.profile.saml2.profile.sso.protocol.SingleLogoutProtocol;
import com.alfaariss.oa.util.logging.RequestorEventLogItem;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.saml2.NameIDFormatter;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.SAML2Requestor;
import com.alfaariss.oa.util.saml2.ISAML2Requestors;
import com.alfaariss.oa.util.saml2.SAML2SecurityException;
import com.alfaariss.oa.util.saml2.StatusException;
import com.alfaariss.oa.util.saml2.binding.AbstractDecodingFactory;
import com.alfaariss.oa.util.saml2.binding.AbstractEncodingFactory;
import com.alfaariss.oa.util.saml2.binding.BindingProperties;
import com.alfaariss.oa.util.saml2.binding.soap11.SOAP11Utils;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;
import com.alfaariss.oa.util.saml2.metadata.role.sso.IDPSSODescriptorBuilder;
import com.alfaariss.oa.util.saml2.profile.AbstractSAML2Profile;
import com.alfaariss.oa.util.saml2.profile.ISAML2Profile;
import com.alfaariss.oa.util.validation.SessionValidator;

/**
 * Single Logout Profile implementation.
 *
 * @author MHO 
 * @author EVB
 * @author Alfa & Ariss
 * @see <a 
 *  href="http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf" 
 *  target="_new">
 *  Profiles for the OASIS Security Assertion Markup Language (SAML) V2.0
 *  </a>
 */
public class SingleLogout extends AbstractSAML2Profile 
{    
    /** Sesstion attribute: ProtocolBinding */
    public final static String SESSION_REQUEST_PROTOCOLBINDING = "ProtocolBinding";
    /** Sesstion attribute: ID */
    public final static String SESSION_REQUEST_ID = "ID";
    /** Sesstion attribute: RelayState */
    public final static String SESSION_REQUEST_RELAYSTATE = "RelayState";
    
    private final static String SSO_LOGOUT_URI = "logout";
    
    private static Log _logger = LogFactory.getLog(SingleLogout.class);
    
    private BindingProperties _bindingProperties;
   
    /** The protocol handler */
    private SingleLogoutProtocol _protocol;
    
    private IDPSSODescriptor _idpSSODescriptor;
     
    
    /**
     * @see AbstractSAML2Profile#init(
     * com.alfaariss.oa.api.configuration.IConfigurationManager, 
     * org.w3c.dom.Element, org.opensaml.saml2.metadata.EntityDescriptor, 
     * java.lang.String, java.lang.String, 
     * com.alfaariss.oa.util.saml2.SAML2Requestors, 
     * com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow, java.lang.String)
     */
    public void init(IConfigurationManager configurationManager,
        Element config, EntityDescriptor entityDescriptor, String sBaseUrl, 
        String sWebSSOPath, ISAML2Requestors requestors, 
        SAML2IssueInstantWindow issueInstantWindow, String sProfileID) 
        throws OAException
    {
        super.init(configurationManager, config, entityDescriptor, sBaseUrl, 
            sWebSSOPath, requestors, issueInstantWindow, sProfileID);
        
        //read bindings config 
        Element eBindings = configurationManager.getSection(config, 
            "bindings");
        if (eBindings == null)
        {
            _logger.error(
                "No 'bindings' section found in 'profile' section in configuration with profile id: " 
                + _sID);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _bindingProperties = new BindingProperties(configurationManager, eBindings);
                
        //read NameID config
        Element eNameID = configurationManager.getSection(config, "nameid");
        if (eNameID == null)
        {
            _logger.error(
                "No 'nameid' section found in 'profile' section in configuration with profile id: " 
                + _sID);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        ITGTAliasStore spAliasStore = _tgtFactory.getAliasStoreSP();
        if (spAliasStore == null)
        {
            _logger.error("TGT Factory has no SP Role alias support");
            throw new OAException(SystemErrors.ERROR_INIT);
        }
        
        NameIDFormatter nameIDFormatter = new NameIDFormatter(
            configurationManager, eNameID, _cryptoManager, spAliasStore);
        
        //Create protocol
        _protocol = new SingleLogoutProtocol(_cryptoManager.getSecureRandom(),
            _sProfileURL, _tgtFactory, nameIDFormatter, 
            _issueInstantWindow, spAliasStore);
        
        //Update metadata
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
            
                processLogoutResponse(servletRequest, servletResponse, 
                    session);
            }
            else
                processSAMLRequest(servletRequest, servletResponse);
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
    }
    
    private void processSAMLRequest(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) throws OAException
    {
        SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject,SAMLObject>  context = null;
        String sBinding = null;
        try
        {
            //Decode message
            AbstractDecodingFactory decFactory = 
                AbstractDecodingFactory.resolveInstance(servletRequest, 
                    servletResponse, _bindingProperties);
            if(decFactory == null)
            {
                _logger.debug("Decoding factory not created: Invalid request");
                throw new MessageDecodingException("Could not determine binding");
            }
    
            SAMLMessageDecoder decoder = decFactory.getDecoder();
            sBinding = decoder.getBindingURI();
            
            _logger.debug("Binding URI: " + sBinding);
            
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
            
            if (requestMessage instanceof LogoutRequest)
            {       
                //DD <LogoutRequest> signing is forced by code for HTTP POST or Redirect binding [saml-profiles-2.0-os r1223].
                boolean bMandatorySinging = 
                    sBinding.equals(SAMLConstants.SAML2_POST_BINDING_URI) ||
                    sBinding.equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
                
                HTTPInTransport inTransport = (HTTPInTransport) context.getInboundMessageTransport();
                String sigParam = inTransport.getParameterValue("Signature");
                boolean bSigned = !DatatypeHelper.isEmpty(sigParam) || requestMessage.isSigned();                                     
                if(bMandatorySinging && !bSigned)
                {
                    _logger.debug(
                        "LogoutRequest MUST be signed if the HTTP POST or Redirect binding is used");
                    throw new SAML2SecurityException(
                        RequestorEvent.REQUEST_INVALID);
                }
                
                //synchronous bindings: The requester MUST authenticate itself 
                //to the identity provider, either by signing the 
                //<LogoutRequest> or using any other binding-supported 
                //mechanism.
                //DD <LogoutRequest> signing is not forced by code for synchronous bindings, but should be enabled by configuration in a production environment
                
                LogoutRequest lr = (LogoutRequest)requestMessage;
                String sReason = lr.getReason();
                
                processLogoutRequest(
                   servletRequest, servletResponse, context, sBinding, sReason);
            }
            else
            {
                _logger.debug("Unsupported SAML message in request");  
                throw new MessageDecodingException(
                    "Unsupported SAML message");
            }
        }
        catch(StatusException e) //SAML processing error
        {
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                e.getEvent(), null, servletRequest.getRemoteAddr(), 
                e.getRequestorID(), this, e.getMessage()));
            
            sendResponse(context, servletRequest, servletResponse, sBinding);
        }
        catch (MessageDecodingException e) //Binding processing error  
        {    
           _logger.debug(
               "Decoding error", e);
           _eventLogger.info(new RequestorEventLogItem(null, null, null, 
               RequestorEvent.REQUEST_INVALID, null, 
               servletRequest.getRemoteAddr(), null, this, null));
           if(sBinding != null && sBinding.equals(
               SAMLConstants.SAML2_SOAP11_BINDING_URI))
           {
               SOAP11Utils.sendSOAPFault(context, 
                   RequestorEvent.REQUEST_INVALID);
           }
           else
           {            
               try
               {
                   if (!servletResponse.isCommitted())
                       servletResponse.sendError(
                           HttpServletResponse.SC_BAD_REQUEST);
               }
               catch (IOException e1)
               {
                   _logger.warn("Could not send response", e1);
               }
           }
        }
        catch (SAML2SecurityException e)
            //The message does not meet the required security constraints
        {  
            _logger.debug(
                "Security error", e);
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                e.getEvent(), null, servletRequest.getRemoteAddr(), 
                null, this, "Security Fault"));
                       
            //DD Security error -> Return a "403 Forbidden" response
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
    
    //Add SingleLogoutService to metadata
    private void updateEntityDescriptor(
        IConfigurationManager configurationManager, Element config)
    {
        _idpSSODescriptor = _entityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
        if (_idpSSODescriptor == null)
            throw new IllegalArgumentException("No IDPSSODescriptor available");
        
        IDPSSODescriptorBuilder builder = new IDPSSODescriptorBuilder(
            configurationManager, config, _idpSSODescriptor);      
       
        builder.buildSingleLogoutService(_sProfileURL, _bindingProperties);
    }
    
    //TODO EVB, MHO (F): Should SAML2 profile support logging out by user at profile itself? [saml-core-2.0-os r2646]
    
    //Handle logout request 
    private void processLogoutRequest(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse,
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject,SAMLObject>  
        context, String sBinding, String sReason) 
        throws OAException, SAML2SecurityException, StatusException
    {          
        //Validate requestor and signature
        validateRequest(context, SPSSODescriptor.DEFAULT_ELEMENT_NAME);
         
        //Process request
        ITGT tgt = _protocol.processRequest(context);
        
        String sInReponseTo = context.getInboundSAMLMessageId();
        String sIssuer = context.getInboundMessageIssuer();
        
        //DD remove the requestor id, if not: the issuer will recieve a logout request
        tgt.removeRequestorID(sIssuer);
        
        boolean bIsPartiallyLogout = false;
        if (sReason != null && sReason.equals(LogoutResponse.SP_TIMEOUT_URI))
        {
            bIsPartiallyLogout = tgt.getRequestorIDs().size() > 0;
        }
        
        if (bIsPartiallyLogout || sBinding.equals(SAMLConstants.SAML2_SOAP11_BINDING_URI))
        {//process synchronous logout

            //Process response        
            _protocol.processResponse(tgt, sInReponseTo, context, bIsPartiallyLogout);
            
            //Send response      
            sendResponse(context, servletRequest, servletResponse, sBinding); 
            
            _eventLogger.info(new UserEventLogItem(null, tgt.getId(), null, 
                UserEvent.USER_LOGGED_OUT, tgt.getUser().getID(),
                servletRequest.getRemoteAddr(), 
                context.getInboundMessageIssuer(), this, 
                context.getOutboundSAMLMessageId()));
        }
        else
        {//process a-synchronous logout
            ISession session = _sessionFactory.createSession(sIssuer);
            
            ISessionAttributes sessionAttributes = session.getAttributes();
            sessionAttributes.put(this.getClass(), SESSION_REQUEST_ID, sInReponseTo);
            sessionAttributes.put(this.getClass(), SESSION_REQUEST_PROTOCOLBINDING, sBinding);
            
            String sRelayState = context.getRelayState();
            if (sRelayState != null)
                sessionAttributes.put(this.getClass(), SESSION_REQUEST_RELAYSTATE, sRelayState);
            
            session.persist();//this generates the session ID
            
            StringBuffer sbProfileURL = new StringBuffer();
            sbProfileURL.append(_sProfileURL);
            sbProfileURL.append("?");
            sbProfileURL.append(ISession.ID_NAME);
            sbProfileURL.append("=");
            sbProfileURL.append(session.getId());
            session.setProfileURL(sbProfileURL.toString());
            
            servletRequest.setAttribute(ISession.ID_NAME, session);
            
            StringBuffer sbForward = new StringBuffer(_sWebSSOPath);
            if (!_sWebSSOPath.endsWith("/"))
                sbForward.append("/");
            sbForward.append(SSO_LOGOUT_URI);
            
            _logger.debug("Forwarding user to: " + sbForward.toString());
            
            RequestDispatcher oDispatcher = 
                servletRequest.getRequestDispatcher(sbForward.toString());
            if(oDispatcher == null)
            {
                _logger.warn(
                    "There is no requestor dispatcher supported with name: " 
                    + sbForward.toString());                    
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            _eventLogger.info(new UserEventLogItem(session, 
                servletRequest.getRemoteAddr(),
                UserEvent.USER_LOGOUT_IN_PROGRESS, this, null));
            try
            {
                oDispatcher.forward(servletRequest, servletResponse);
            }
            catch (Exception e)
            {
                _logger.fatal("Could not forward user", e);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
    }
    
    private void processLogoutResponse(HttpServletRequest request, 
        HttpServletResponse response, ISession session) 
        throws OAException, UserException
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
            
            if (session.isExpired())
            {
                StringBuffer sbError = new StringBuffer(
                    "Expired session with id '");
                sbError.append(session.getId());
                sbError.append("' found in request sent from IP: ");
                sbError.append(request.getRemoteAddr());
                _logger.debug(sbError.toString());
                throw new UserException(UserEvent.SESSION_EXPIRED);
            }
            
            ISessionAttributes sessionAttributes = session.getAttributes();
            
            String sInResponseTo = (String)sessionAttributes.get(this.getClass(), SESSION_REQUEST_ID);
            if (sInResponseTo == null)
            {
                StringBuffer sbDebug = new StringBuffer("No session attribute available with name '");
                sbDebug.append(SESSION_REQUEST_ID);
                sbDebug.append("' in session with ID: ");
                sbDebug.append(session.getId());
                _logger.debug(sbDebug.toString());
                throw new UserException(UserEvent.SESSION_INVALID);
            }
    
            String sRequestBinding = (String)sessionAttributes.get(this.getClass(), SESSION_REQUEST_PROTOCOLBINDING);
            if (sRequestBinding == null)
            {
                StringBuffer sbDebug = new StringBuffer("No session attribute available with name '");
                sbDebug.append(SESSION_REQUEST_PROTOCOLBINDING);
                sbDebug.append("' in session with ID: ");
                sbDebug.append(session.getId());
                _logger.debug(sbDebug.toString());
                throw new UserException(UserEvent.SESSION_INVALID);
            }
            
            String sRelayState = (String)sessionAttributes.get(this.getClass(), SESSION_REQUEST_RELAYSTATE);
            if (sRelayState != null)
                context.setRelayState(sRelayState);
            
            context.setLocalEntityId(_sEntityID);//needed by processResponse()
            
            UserEvent userEvent = UserEvent.INTERNAL_ERROR;
            switch (session.getState())
            {
                case USER_LOGOUT_SUCCESS:
                {
                    _protocol.processResponse(null, sInResponseTo, context);
                    userEvent = UserEvent.USER_LOGGED_OUT;
                    break;
                }
                case USER_LOGOUT_PARTIAL:
                {
                    _protocol.buildErrorResponse(context, StatusCode.SUCCESS_URI,
                        StatusCode.PARTIAL_LOGOUT_URI, sInResponseTo);
                    userEvent = UserEvent.USER_LOGOUT_PARTIALLY;
                    break;
                }
                case USER_LOGOUT_IN_PROGRESS:
                case USER_LOGOUT_FAILED:
                {
                    _protocol.buildErrorResponse(context, StatusCode.RESPONDER_URI, 
                        null, sInResponseTo);
                    userEvent = UserEvent.USER_LOGOUT_FAILED;
                    break;
                }
                default:
                {
                    StringBuffer sbError = new StringBuffer(
                        "Unsupported session state '");
                    sbError.append(session.getState());
                    sbError.append("' for session with id: ");
                    sbError.append(session.getId());
                    _logger.debug(sbError.toString());
                    throw new UserException(UserEvent.REQUEST_INVALID);
                }
            }
            
            //Send response      
            sendASynchronousResponse(context, request, response, sRequestBinding, saml2Requestor);
            
            _eventLogger.info(new UserEventLogItem(session, 
                request.getRemoteAddr(), userEvent, this, 
                context.getOutboundSAMLMessageId()));
        }
        catch (UserException e)
        {
            throw e;
        }
        finally
        {
            //Always remove logout session; even if an error ocurred
            if (session != null)
            {
                session.expire();
                session.persist();
            }
        }
    }
    
    //Send SAML response message using given binding
    private void sendASynchronousResponse(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject,SAMLObject> context, 
        HttpServletRequest servletRequest,  
        HttpServletResponse servletResponse, 
        String sRequestBinding,
        SAML2Requestor saml2Requestor) 
        throws OAException
    {
        try
        {
            LogoutResponse logoutResponse = (LogoutResponse)context.getOutboundSAMLMessage();
            
            //Response must be signed if POST, Redirect binding is used
            if(!_signingEnabled)
            {
                _logger.warn(
                    "No outbound signing credential found: responses must be signed, make sure server signing is enabled");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            //resolve LogoutService destination using metadata               
            SingleLogoutService singleLogoutService = 
                resolveSingleLogoutServiceEndpoint(saml2Requestor, sRequestBinding);      
            if(singleLogoutService == null)
            {
                StringBuffer sbWarning = new StringBuffer("No SingleLogoutService with supported binding for response available (");
                sbWarning.append(sRequestBinding);
                sbWarning.append(") for requestor with ID: ");
                sbWarning.append(saml2Requestor.getID());
                _logger.warn(sbWarning.toString());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            String sBindingURI = singleLogoutService.getBinding();
            
            String sDestination =  singleLogoutService.getResponseLocation();
            if(sDestination == null) //No response location
            {
                _logger.debug("No SingleLogoutService response location for response available, using 'location'");
                //Try location
                sDestination = singleLogoutService.getLocation();
            }
            else
            {
                //DD Copy response location to location: OpenSAML encoders only support response location for Response objects, LogoutResponse is not a Response
                singleLogoutService.setLocation(sDestination);
            }
            
            if (sDestination == null)
            {           
                _logger.warn(
                    "No SingleLogoutService location for response available");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            logoutResponse.setDestination(sDestination);    
            
            //Add my metadata
            context.setLocalEntityMetadata(_entityDescriptor);
            context.setLocalEntityRoleMetadata(_idpSSODescriptor);
            
            context.setPeerEntityEndpoint(singleLogoutService);
            
            //Prepare the response signing
            if (_signingEnabled)
            {
                Credential credentials = SAML2CryptoUtils.retrieveMySigningCredentials(
                    _cryptoManager, _entityDescriptor.getEntityID());  
                context.setOutboundSAMLMessageSigningCredential(credentials);
            }
            
            AbstractEncodingFactory encodingFactory = 
                AbstractEncodingFactory.createInstance(servletRequest, 
                    servletResponse, sBindingURI, _bindingProperties);    
            
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
            _logger.error("Could not send reponse", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    //Send SAML response message using given binding
    private void sendResponse(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject,SAMLObject> context, 
        HttpServletRequest servletRequest,  
        HttpServletResponse servletResponse, String sRequestBinding) 
        throws OAException
    {
        try
        {
            LogoutResponse logoutResponse = (LogoutResponse)context.getOutboundSAMLMessage();
            LogoutRequest logoutRequest = (LogoutRequest)context.getInboundSAMLMessage();
            
            //Prepare the response signing
            if (_signingEnabled)
            {
                Credential credentials = SAML2CryptoUtils.retrieveMySigningCredentials(
                    _cryptoManager, _sEntityID);  
                context.setOutboundSAMLMessageSigningCredential(credentials);
            }
            
            String sBindingURI = null;                                 
           
            if(sRequestBinding.equals(SAMLConstants.SAML2_SOAP11_BINDING_URI))
            {
                sBindingURI = SAMLConstants.SAML2_SOAP11_BINDING_URI;
            }
            else 
            {//ASynchronous
                
                //The following code is to send error responses with asynchronous bindings, if the request was invalid.
                
                //Response must be signed if POST, Redirect binding is used
                if(!_signingEnabled)
                {
                    _logger.warn(
                        "No outbound signing credential found: responses must be signed, make sure server signing is enabled");
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                String sRequestor = context.getInboundMessageIssuer();
                
                IRequestor oRequestor = 
                    _requestorPoolFactory.getRequestor(sRequestor);
                if (oRequestor == null)
                {
                    _logger.debug("No OA Requestor found with id: " + sRequestor);
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                SAML2Requestor requestor = _requestors.getRequestor(oRequestor);
                if (requestor == null)
                {           
                    _logger.warn(
                        "No SingleLogoutService location for response available, no requestor information configured. Request ID: " 
                        + logoutRequest.getID());
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                //resolve LogoutService destination using metadata               
                SingleLogoutService singleLogoutService = 
                    resolveSingleLogoutServiceEndpoint(requestor, sRequestBinding);      
                
                if(singleLogoutService == null)
                {
                    StringBuffer sbWarning = new StringBuffer("No SingleLogoutService with supported binding (");
                    sbWarning.append(sRequestBinding);
                    sbWarning.append(") for response available. Request ID ");
                    sbWarning.append(logoutRequest.getID());
                    _logger.warn(sbWarning.toString());
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                sBindingURI = singleLogoutService.getBinding();
                
                
                String sDestination =  singleLogoutService.getResponseLocation();
                if(sDestination == null) //No response location
                {
                    _logger.debug(
                        "No SingleLogoutService response location for response available, using 'location'. Request ID: " 
                        + logoutRequest.getID());
                    //Try location
                    sDestination =  singleLogoutService.getLocation();
                }
                else
                {
                    //DD Copy response location to location: OpenSAML encoders only support response location for Response objects, LogoutResponse is not a Response
                    singleLogoutService.setLocation(sDestination);
                }
                
                if (sDestination == null)
                {           
                    _logger.warn(
                        "No SingleLogoutService location for response available. Request ID: " 
                        + logoutRequest.getID());
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                logoutResponse.setDestination(sDestination);                                                                
                context.setPeerEntityEndpoint(singleLogoutService);
            }            
            
            AbstractEncodingFactory encodingFactory = 
                AbstractEncodingFactory.createInstance(servletRequest, 
                    servletResponse, sBindingURI, _bindingProperties);       
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
            _logger.error("Could not send reponse", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private SingleLogoutService resolveSingleLogoutServiceEndpoint(
        SAML2Requestor requestor, String sRequestedBinding) 
        throws OAException
    {
        assert requestor != null : "Empty SAML2 requestor";
        try
        {
            //DD Metadata is mandatory for asynchronous logout
            MetadataProvider oMetadataProvider = 
                requestor.getMetadataProvider(); 
            if(oMetadataProvider == null)
            {
                _logger.warn(
                    "No ChainingMetadataProvider found for requestor: " 
                    + requestor.getID());
                throw new OAException(SystemErrors.ERROR_INTERNAL);  
            }
            
            SPSSODescriptor spSSODescriptor = 
                (SPSSODescriptor)oMetadataProvider.getRole(
                    requestor.getID(), 
                    SPSSODescriptor.DEFAULT_ELEMENT_NAME, 
                    SAMLConstants.SAML20P_NS);
            if (spSSODescriptor == null)
            {
                _logger.warn(
                    "No SPSSODescriptor in metadata: Can't resolve response target for requestor: " 
                    + requestor.getID());                
                throw new OAException(SystemErrors.ERROR_INTERNAL);                 
            }
            
            SingleLogoutService service = null;
            List<SingleLogoutService> singleLogoutServices = 
                spSSODescriptor.getSingleLogoutServices();
            
            String sDefault = _bindingProperties.getDefault();
            SingleLogoutService defaultService = null;
            for(SingleLogoutService tempService: singleLogoutServices)
            {               
                String sBinding = tempService.getBinding();                
                if(sBinding != null && _bindingProperties.isSupported(sBinding))
                {  
                    if (sBinding.equals(sRequestedBinding))
                    {
                        service = tempService;
                        break;
                    }
                    else if(defaultService == null && sBinding.equals(sDefault))
                    {
                        defaultService = tempService;
                    }
                }
            }   
            
            if (service == null)
                service = defaultService;
            
            return service;                        
        }
        catch(OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not resolve SingleLogoutService", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
}
