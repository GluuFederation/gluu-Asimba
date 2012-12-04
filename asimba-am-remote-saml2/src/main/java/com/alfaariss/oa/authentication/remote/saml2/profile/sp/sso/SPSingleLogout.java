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
package com.alfaariss.oa.authentication.remote.saml2.profile.sp.sso;

import java.io.IOException;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004Builder;
import org.opensaml.saml2.binding.security.SAML2HTTPPostSimpleSignRule;
import org.opensaml.saml2.binding.security.SAML2HTTPRedirectDeflateSignatureRule;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.ChainingCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.StaticCredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.idmapper.IIDMapper;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.authentication.remote.saml2.SAML2AuthNConstants;
import com.alfaariss.oa.authentication.remote.saml2.profile.sp.sso.protocol.SingleLogoutProtocol;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoException;
import com.alfaariss.oa.engine.core.idp.IDPStorageManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.util.logging.RequestorEventLogItem;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.saml2.NameIDFormatter;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.SAML2Requestors;
import com.alfaariss.oa.util.saml2.SAML2SecurityException;
import com.alfaariss.oa.util.saml2.StatusException;
import com.alfaariss.oa.util.saml2.binding.AbstractDecodingFactory;
import com.alfaariss.oa.util.saml2.binding.AbstractEncodingFactory;
import com.alfaariss.oa.util.saml2.binding.BindingProperties;
import com.alfaariss.oa.util.saml2.binding.soap11.SOAP11Utils;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;
import com.alfaariss.oa.util.saml2.metadata.role.sso.SPSSODescriptorBuilder;
import com.alfaariss.oa.util.saml2.profile.AbstractSAML2Profile;
import com.alfaariss.oa.util.validation.SessionValidator;

/**
 * SLO Profile for use in SAML2 Profile.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.1
 */
public class SPSingleLogout extends AbstractSAML2Profile
{
    /** Sesstion attribute: ProtocolBinding */
    public final static String SESSION_REQUEST_PROTOCOLBINDING = "ProtocolBinding";
    /** Sesstion attribute: ID */
    public final static String SESSION_REQUEST_ID = "ID";
    /** Sesstion attribute: RelayState */
    public final static String SESSION_REQUEST_RELAYSTATE = "RelayState";
    
    private final static String SSO_LOGOUT_URI = "logout";

    private Log _logger;
    private BindingProperties _bindingProperties;
    private SingleLogoutProtocol _protocol;
    private IIDMapper _idMapper;
    private IDPStorageManager _idpStorageManager;
    private SPSSODescriptor _spSSODescriptor;
    private Hashtable<String, Boolean> _htLogoutReasonActions;
    
    /**
     * Constructor.
     */
    public SPSingleLogout()
    {
        _logger = LogFactory.getLog(this.getClass());
        _htLogoutReasonActions = new Hashtable<String, Boolean>();
    }
    
    /**
     * @see com.alfaariss.oa.util.saml2.profile.AbstractSAML2Profile#init(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element, org.opensaml.saml2.metadata.EntityDescriptor, java.lang.String, java.lang.String, com.alfaariss.oa.util.saml2.SAML2Requestors, com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow, java.lang.String)
     */
    public void init(IConfigurationManager oConfigurationManager,
        Element eConfig, EntityDescriptor entityDescriptor, String sBaseUrl, 
        String sWebSSOPath, SAML2Requestors requestors, 
        SAML2IssueInstantWindow issueInstantWindow, String sProfileID) 
        throws OAException
    {
        super.init(oConfigurationManager, eConfig, entityDescriptor, sBaseUrl, 
            sWebSSOPath, requestors, issueInstantWindow, sProfileID);

        //read bindings config
        Element eBindings = oConfigurationManager.getSection(eConfig, "bindings");
        if (eBindings == null)
        {
            _logger.error("No 'bindings' section found in 'profile' section in configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _bindingProperties = new BindingProperties(oConfigurationManager, eBindings);
        
        ITGTAliasStore idpAliasStore = _tgtFactory.getAliasStoreIDP();
        if (idpAliasStore == null)
        {
            _logger.error("TGT Factory has no IdP Role alias support");
            throw new OAException(SystemErrors.ERROR_INIT);
        }
        
        //read NameID config
        Element eNameID = oConfigurationManager.getSection(eConfig, "nameid");
        if (eNameID == null)
        {
            _logger.error(
                "No 'nameid' section found in 'profile' section in configuration with profile id: " 
                + _sID);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        Element eIDMapper = oConfigurationManager.getSection(eConfig, "idmapper");
        if (eIDMapper != null)
            _idMapper = createIDMapper(oConfigurationManager, eIDMapper);
        
        NameIDFormatter nameIDFormatter = new NameIDFormatter(
            oConfigurationManager, eNameID, _cryptoManager, idpAliasStore);
        
        //Create protocol
        _protocol = new SingleLogoutProtocol(_cryptoManager.getSecureRandom(),
            _sProfileURL, _tgtFactory, nameIDFormatter, _issueInstantWindow, 
            _idMapper);
        
        updateEntityDescriptor(oConfigurationManager, eConfig);
        
        _idpStorageManager = Engine.getInstance().getIDPStorageManager();
        
        Element eReasons = oConfigurationManager.getSection(eConfig, "reasons");
        if (eReasons == null)
        {
            _logger.info("No optional 'reasons' section found in configuration, using defaults");
        }
        else
        {
            readReasonConfig(oConfigurationManager, eReasons);
        }
    }
    
    /**
     * @see com.alfaariss.oa.util.saml2.profile.ISAML2Profile#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
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
            
                processResponse(servletRequest, servletResponse, session);
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
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not process request", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    
    /**
     * @see com.alfaariss.oa.util.saml2.profile.AbstractSAML2Profile#destroy()
     */
    public void destroy()
    {
        if (_idMapper != null)
            _idMapper.stop();
        
        super.destroy();
    }

    /**
     * Validate a inbound message signature and/or simple signature.
     * @param context The message context.
     * @param saml2IDP The IDP. 
     * @param issuer The inbound message issuer
     * @return <code>true</code> if signature is valid, otherwise <code>false</code>. 
     * @throws OAException If validation fails due to internal error.
     */
    protected boolean validateSignature(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context,
        SAML2IDP saml2IDP, String issuer) throws OAException 
    {       
        boolean bValid = false;       
        try
        {            
            // requestMessage == null is checked
            SignableSAMLObject message = context.getInboundSAMLMessage();
            
            Signature signature = message.getSignature(); 
            if(message.isSigned())
            {               
                //Validate against profile in order to prevent certain types 
                //of denial-of-service attacks associated with signature verification
                _profileValidator.validate(signature);                               
            }                                
            
            //Create ChainingCredentialResolver
            ChainingCredentialResolver chainingCredentialResolver =  
                new ChainingCredentialResolver();           
               
            //TODO EVB, JRE, RDV: define order of credential resolvers and test
                         
            //Metadata credentials
            if(saml2IDP != null)
            {
                MetadataProvider mdProvider = 
                    saml2IDP.getMetadataProvider();
                if(mdProvider != null) //Metadata provider available
                {
                    _logger.debug(
                        "Metadata provider found for issuer: " + issuer);
                    MetadataCredentialResolver mdCredResolver = 
                        new MetadataCredentialResolver(mdProvider);
                    chainingCredentialResolver.getResolverChain().add(mdCredResolver);
                }
            }
            
            //OA Engine credentials
            try
            {               
                if(_signingEnabled) //OA Signing enabled
                {
                    Credential signingCred = 
                        SAML2CryptoUtils.retrieveSigningCredentials(
                            _cryptoManager, issuer);                   
                    StaticCredentialResolver oaResolver = 
                        new StaticCredentialResolver(signingCred);
                    chainingCredentialResolver.getResolverChain().add(oaResolver);
                }
            }
            catch(CryptoException e) //No certificate found
            {
                _logger.debug(
                    "No trusted certificate found for issuer: " + issuer);
                //Ignore
            }   
            
            //TODO EVB, JRE, RDV: define order of credential resolvers and test                        
            if(chainingCredentialResolver.getResolverChain().isEmpty())
            {
                _logger.warn(
                    "No trusted certificate or metadata found for issuer: " + issuer);
                //bValid = false already    
            }
            else
            {               
                //Create trust engine                
                //TODO EVB: trust engine and resolver creation can be placed in one-time init code (e.g. SAML2Requestor)
                SignatureTrustEngine  sigTrustEngine = 
                    new ExplicitKeySignatureTrustEngine(
                        chainingCredentialResolver, _keyInfoCredResolver);
                
                if(message.isSigned()) //Validate XML signature (if applicable)
                {    
                    //create criteria set            
                    CriteriaSet criteriaSet = new CriteriaSet();
                    criteriaSet.add(new EntityIDCriteria(issuer));
                    MetadataCriteria mdCriteria = new MetadataCriteria(
                        context.getPeerEntityRole(), 
                        context.getInboundSAMLProtocol());
                    criteriaSet.add(mdCriteria);
                    criteriaSet.add(new UsageCriteria(UsageType.SIGNING) );
                    bValid = sigTrustEngine.validate(signature, criteriaSet); 
                }   
                else
                    bValid = true; //Message itself not signed
                
                if(bValid) //Message not signed or valid signature
                {
                    //Validate simple signature for GET (if applicable)
                    SAML2HTTPRedirectDeflateSignatureRule ruleGET = 
                        new SAML2HTTPRedirectDeflateSignatureRule(sigTrustEngine);
                    ruleGET.evaluate(context);
                    //Validate simple signature for POST (if applicable)
                    SAML2HTTPPostSimpleSignRule rulePOST = 
                        new SAML2HTTPPostSimpleSignRule(sigTrustEngine, 
                            _pool, _keyInfoCredResolver);
                    rulePOST.evaluate(context);
                }
             }                                   
        }       
        catch(SecurityPolicyException e)
        {
            // Indicates signature was not cryptographically valid, or possibly a processing error
            _logger.debug("Invalid signature", e);
            bValid = false;    
        }
        catch (ValidationException e) 
        {
            // Indicates signature was not cryptographically valid, or possibly a processing error
            _logger.debug("Invalid signature", e);
            bValid = false;                
        }
        catch (SecurityException e) //Internal processing error
        {
            _logger.error("Processing error evaluating the signature", e);           
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return bValid;
    }
    
    private void readReasonConfig(IConfigurationManager configurationManager,
        Element config) throws OAException
    {
        _htLogoutReasonActions.clear();
        
        Element eReason = configurationManager.getSection(config, "reason");
        while (eReason != null)
        {
            String sURI = configurationManager.getParam(eReason, "uri");
            if (sURI == null)
            {
                _logger.error("No 'uri' parameter in 'reason' section found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            if (_htLogoutReasonActions.containsKey(sURI))
            {
                _logger.error("Invalid 'uri' parameter in 'reason' section found in configuration; not unique: " + sURI);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            String sPartial = configurationManager.getParam(eReason, "partial");
            if (sPartial == null)
            {
                _logger.error("No 'partial' parameter in 'reason' section found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Boolean boolPartial = new Boolean(Boolean.TRUE);
            if (sPartial.equalsIgnoreCase("FALSE"))
                boolPartial = new Boolean(Boolean.FALSE);
            else if (!sPartial.equalsIgnoreCase("TRUE"))
            {
                _logger.error("Unknown value in 'partial' configuration item: " 
                    + sPartial);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _htLogoutReasonActions.put(sURI, boolPartial);
            
            StringBuffer sbInfo = new StringBuffer("Using logout action for reason is '");
            sbInfo.append(sURI);
            sbInfo.append("': ");
            _logger.info(sbInfo.toString() + (boolPartial.booleanValue() ? "partial" : "full"));
            
            eReason = configurationManager.getNextSection(eReason);
        }
    }
    
    private void processSAMLRequest(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) throws OAException
    {
        SAMLMessageContext<SignableSAMLObject, 
            SignableSAMLObject,SAMLObject> context = null;
        String sBindingURI = null;
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
            sBindingURI = decoder.getBindingURI();
            
            if (!_bindingProperties.isSupported(sBindingURI))
            {
                _logger.error("The binding is not supported by this protocol: " 
                    + sBindingURI);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            _logger.debug("Binding URI: " + sBindingURI);
            
            context = decFactory.getContext();
            context.setLocalEntityId(_sEntityID);
            context.setLocalEntityMetadata(_entityDescriptor);
            context.setLocalEntityRoleMetadata(_spSSODescriptor);
            
            String val = servletRequest.getParameter("SAMLart");
            if (val != null)
            {
                //SAML artifact received, requestor metadata and IssuerID must be added
                //in order to enable the decoder to decode artifact
                
                byte[] bb = Base64.decode(val);
                SAML2ArtifactType0004 b = null;
                SAML2ArtifactType0004Builder bf = new SAML2ArtifactType0004Builder();
                b = bf.buildArtifact(bb);
                
                IIDP org = _idpStorageManager.getIDP(b.getSourceID(), SAML2IDP.TYPE_SOURCEID);
                if (org != null && org instanceof SAML2IDP)
                {
                    SAML2IDP saml2IDP = (SAML2IDP)org;
                    context.setMetadataProvider(saml2IDP.getMetadataProvider());
                    context.setInboundMessageIssuer(saml2IDP.getID());
                    context.setOutboundMessageIssuer(_sEntityID);
                }
                else
                {
                    StringBuffer sbDebug = new StringBuffer("Unknown organization specified with with SourceID '");
                    sbDebug.append(Arrays.toString(b.getSourceID()));
                    sbDebug.append("' in artifact: ");
                    sbDebug.append(val);
                    _logger.debug(sbDebug.toString());
                    throw new MessageDecodingException("Could not find metadata for decoding artifact");
                }
            }
            
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
            
            if (requestMessage instanceof LogoutResponse)
            {
                processLogoutResponse(servletRequest, servletResponse, context, 
                    (LogoutResponse)requestMessage);
            }
            else if (requestMessage instanceof LogoutRequest)
            {
                //DD <LogoutRequest> signing is forced by code for HTTP POST or Redirect binding [saml-profiles-2.0-os r1223].
                boolean bMandatorySinging = 
                    sBindingURI.equals(SAMLConstants.SAML2_POST_BINDING_URI) ||
                    sBindingURI.equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
                
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
                
                LogoutRequest lr = (LogoutRequest)requestMessage;
                String sReason = lr.getReason();
                
                processLogoutRequest(servletRequest, servletResponse, 
                    context, sBindingURI, sReason);
            }
            else
            {
                _logger.debug("Unsupported SAML message in request from issuer: " 
                    + context.getInboundMessageIssuer());  
                throw new MessageDecodingException("Unsupported SAML message");
            }
        }
        catch(StatusException e) //SAML processing error
        {
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                e.getEvent(), null, servletRequest.getRemoteAddr(), 
                e.getRequestorID(), this, e.getMessage()));
            
            sendResponse(context, servletRequest, servletResponse, sBindingURI);
        }
        catch (MessageDecodingException e) //Binding processing error  
        {    
           _logger.debug("Decoding error", e);
           _eventLogger.info(new RequestorEventLogItem(null, null, null, 
               RequestorEvent.REQUEST_INVALID, null, 
               servletRequest.getRemoteAddr(), null, this, null));
           if(sBindingURI != null && sBindingURI.equals(
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
        {//The message does not meet the required security constraints
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

    //Handle logout request 
    private void processLogoutRequest(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse,
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject,SAMLObject>  
        context, String sBinding, String sReason) 
        throws OAException, SAML2SecurityException, StatusException
    {          
        //Validate requestor and signature
        SAML2IDP saml2IDP = validateRequestMessage(context, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        
        //Process request
        ITGT tgt = _protocol.processRequest(context);

        String sInReponseTo = context.getInboundSAMLMessageId();
                
        boolean bIsPartiallyLogout = false;
        if (sReason != null)
        {
            if (_htLogoutReasonActions.containsKey(sReason))
            {//The reason logout action can be optionally configured
                bIsPartiallyLogout = _htLogoutReasonActions.get(sReason).booleanValue();
            }
            else
            {
                if (sReason.equals(LogoutResponse.GLOBAL_TIMEOUT_URI))
                {//More info about this reason: saml-core-2.0-o.s.pdf r2662
                    bIsPartiallyLogout = true;
                }
                else if (sReason.equals(LogoutResponse.SP_TIMEOUT_URI))
                {//More info about this reason: saml-core-2.0-o.s.pdf r2665
                    //it is agreed with the requestor that we must do a full logout
                    bIsPartiallyLogout = false;
                }
                else if (sReason.equals(LogoutResponse.USER_LOGOUT_URI))
                {//More info about this reason: saml-core-2.0-o.s.pdf r2580
                    bIsPartiallyLogout = false;
                }
                else if (sReason.equals(LogoutResponse.ADMIN_LOGOUT_URI))
                {//More info about this reason: saml-core-2.0-o.s.pdf r2583
                    bIsPartiallyLogout = false;
                } 
            }
        }
                
        if (bIsPartiallyLogout || sBinding.equals(SAMLConstants.SAML2_SOAP11_BINDING_URI))
        {   
            //Process response
            _protocol.processResponse(tgt, sInReponseTo, context, bIsPartiallyLogout);
                  
            context.setOutboundMessageIssuer(saml2IDP.getID());
            context.setMetadataProvider(saml2IDP.getMetadataProvider());
            
            //Send response      
            sendResponse(context, servletRequest, servletResponse, sBinding);
            
            _eventLogger.info(new UserEventLogItem(null, tgt.getId(), null, 
                UserEvent.USER_LOGGED_OUT, tgt.getUser().getID(),
                servletRequest.getRemoteAddr(), saml2IDP.getID(), this, 
                context.getOutboundSAMLMessageId()));
        }
        else
        {//process a-synchronous logout
            
            //DD Creating a session with an OpenASelect IdP instead of an OpenASelect Requestor has the consequence that any SP Aliasses for a requestor with the same ID will be removed 
            ISession session = _sessionFactory.createSession(saml2IDP.getID());
            
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
    
    private void processResponse(HttpServletRequest request, 
        HttpServletResponse response, ISession session) 
        throws OAException, UserException
    {
        try
        {
            String sIssuer = session.getRequestorId();
            if (_idpStorageManager.existStorage(sIssuer))
            {
                _logger.debug("No IDP found with for issuer: " + sIssuer);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            SAML2IDP saml2IDP = (SAML2IDP)_idpStorageManager.getIDP(sIssuer);
                        
            SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
                context = createEncodingContext(request, response);
            context.setInboundMessageIssuer(_sEntityID);
            context.setOutboundMessageIssuer(saml2IDP.getID());
            context.setMetadataProvider(saml2IDP.getMetadataProvider());
            
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
            
            sendASynchronousResponse(context, request, response, sRequestBinding, saml2IDP);
            
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

    private void processLogoutResponse(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse,
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject,SAMLObject>  
        context, LogoutResponse message) throws OAException, SAML2SecurityException 
    {
        String sInResponseTo = message.getInResponseTo();
        if (sInResponseTo == null)
        {
            _logger.debug("Incoming SAML object is missing InResponseTo attribute");
            throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
        }

        //DD: Session ID is extracted from InResponseTo. If null, relaystate or target are used for Unsolicited Response.
        String sSessionID = null;
        String sRequestIDPrefix = null;
        if (sInResponseTo.length() <= SAML2AuthNConstants.REQUEST_ID_LENGTH)
        {
            StringBuffer sbWarn = new StringBuffer("Invalid InResponseTo ID supplied (");
            sbWarn.append(sInResponseTo);
            sbWarn.append(") is must have a length that is at least bigger then: ");
            sbWarn.append(SAML2AuthNConstants.REQUEST_ID_LENGTH);
            _logger.warn(sbWarn.toString());
            
            throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
        }
        
        sRequestIDPrefix = sInResponseTo.substring(0, SAML2AuthNConstants.REQUEST_ID_LENGTH);
        sSessionID = sInResponseTo.substring(SAML2AuthNConstants.REQUEST_ID_LENGTH);
        
        if(!SessionValidator.validateDefaultSessionId(sSessionID))
        {
            StringBuffer sbError = new StringBuffer("Invalid '");
            sbError.append(ISession.ID_NAME);
            sbError.append("' in request: ");
            sbError.append(sSessionID);
            _logger.debug(sbError.toString());
            throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
        } 
        
        ISession session = _sessionFactory.retrieve(sSessionID);
        
        if (session == null || session.isExpired())
        {
            _logger.debug("Could not process SAML response; Session expired");
            throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
        }
        
        if (session.getAttributes().contains(SAML2AuthNConstants.class, 
            SAML2AuthNConstants.AUTHNREQUEST_ID_PREFIX))
        {
            String sSessionRequestIDPrefix = 
                (String)session.getAttributes().get(SAML2AuthNConstants.class, 
                SAML2AuthNConstants.AUTHNREQUEST_ID_PREFIX);
            
            if (sSessionRequestIDPrefix != null 
                && sRequestIDPrefix != null
                && !sSessionRequestIDPrefix.equals(sRequestIDPrefix))
            {
                StringBuffer sbError = new StringBuffer("Invalid InResponseTo session ID prefix in request: expected '");
                sbError.append(sSessionRequestIDPrefix);
                sbError.append("' but recieved: ");
                sbError.append(sRequestIDPrefix);
                _logger.debug(sbError.toString());
                throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
            }
        }
        
        //forward user to /sso to finish logout (in authn.saml2 where result will be checked)
        
        servletRequest.setAttribute(SAML2AuthNConstants.SESSION_ATTRIBUTE_NAME, context);
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
    
    private void updateEntityDescriptor(
        IConfigurationManager configurationManager, Element config)
    {        
        _spSSODescriptor = 
            _entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        if (_spSSODescriptor == null)
            throw new IllegalArgumentException("No SPSSODescriptor available");
        
        SPSSODescriptorBuilder builder = new SPSSODescriptorBuilder(
            configurationManager, config, _spSSODescriptor);      
       
        builder.buildSingleLogoutService(_sProfileURL, _bindingProperties);
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
            else //ASynchronous
            {
                //Response must be signed if POST, Redirect binding is used
                if(!_signingEnabled)
                {
                    _logger.warn(
                        "No outbound signing credential found: responses must be signed, make sure server signing is enabled");
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                String sIssuer = context.getInboundMessageIssuer();
                
                if (_idpStorageManager.existStorage(sIssuer))
                {
                    _logger.debug("No IDP found with for issuer: " + sIssuer);
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                SAML2IDP saml2IDP = (SAML2IDP)_idpStorageManager.getIDP(sIssuer);
                
                //resolve LogoutService destination using metadata               
                SingleLogoutService singleLogoutService = 
                    resolveSingleLogoutServiceEndpoint(saml2IDP, sRequestBinding);      
                
                if(singleLogoutService == null)
                {
                    _logger.warn(
                        "No SingleLogoutService with supported binding for response available. Request ID: " 
                        +  logoutRequest.getID());
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
        catch (Exception e)
        {
            _logger.error("Internal error when sending reponse", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    //Send SAML response message using given binding
    private void sendASynchronousResponse(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject,SAMLObject> context, 
        HttpServletRequest servletRequest,  
        HttpServletResponse servletResponse, 
        String sRequestBinding,
        SAML2IDP saml2IDP) 
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
                resolveSingleLogoutServiceEndpoint(saml2IDP, sRequestBinding); 
               
            if(singleLogoutService == null)
            {
                StringBuffer sbWarning = new StringBuffer("No SingleLogoutService with supported binding for response available (");
                sbWarning.append(sRequestBinding);
                sbWarning.append(") for SAML2 IdP with ID: ");
                sbWarning.append(saml2IDP.getID());
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
            context.setLocalEntityRoleMetadata(_spSSODescriptor);
            
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
    
    private SingleLogoutService resolveSingleLogoutServiceEndpoint(
        SAML2IDP saml2IDP, String sRequestBinding) throws OAException
    {
        assert saml2IDP != null : "Empty SAML2 IDP supplied";
        try
        {
            //DD Metadata is mandatory for asynchronous logout
            MetadataProvider metadataProvider = saml2IDP.getMetadataProvider(); 
            if(metadataProvider == null)
            {
                _logger.warn(
                    "No MetadataProvider found for IDP: " 
                    + saml2IDP.getID());
                throw new OAException(SystemErrors.ERROR_INTERNAL);  
            }
            
            IDPSSODescriptor idpSSODescriptor = 
                (IDPSSODescriptor)metadataProvider.getRole(
                    saml2IDP.getID(), 
                    IDPSSODescriptor.DEFAULT_ELEMENT_NAME, 
                    SAMLConstants.SAML20P_NS);
            if (idpSSODescriptor == null)
            {
                _logger.warn(
                    "No IDPSSODescriptor in metadata: Can't resolve response target for IDP: " 
                    + saml2IDP.getID());                
                throw new OAException(SystemErrors.ERROR_INTERNAL);                 
            }
            
            SingleLogoutService service = null;
            List<SingleLogoutService> singleLogoutServices = 
                idpSSODescriptor.getSingleLogoutServices();
            
            String sDefault = _bindingProperties.getDefault();
            SingleLogoutService defaultService = null;
            for(SingleLogoutService tempService: singleLogoutServices)
            {
                String sBinding = tempService.getBinding();                
                if(sBinding != null && _bindingProperties.isSupported(sBinding))
                {  
                    if (sBinding.equals(sRequestBinding))
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
            _logger.fatal("Could not resolve SingleLogoutService for: " + saml2IDP.getID(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private IIDMapper createIDMapper(IConfigurationManager configManager, 
        Element eConfig) throws OAException
    {
        IIDMapper oMapper = null;
        try
        {
            String sClass = configManager.getParam(eConfig, "class");
            if (sClass == null)
            {
                _logger.error("No 'class' parameter found in 'idmapper' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Class cMapper = null;
            try
            {
                cMapper = Class.forName(sClass);
            }
            catch (Exception e)
            {
                _logger.error("No 'class' found with name: " + sClass, e);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            try
            {
                oMapper = (IIDMapper)cMapper.newInstance();
            }
            catch (Exception e)
            {
                _logger.error("Could not create an 'IIDMapper' instance of the configured 'class' found with name: " 
                    + sClass, e);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            oMapper.start(configManager, eConfig);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during creation of id mapper", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return oMapper;
    }
    
    private SAML2IDP validateRequestMessage(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context, QName role) 
        throws SAML2SecurityException, OAException
    {   
        context.setPeerEntityRole(role);       
        String sIssuer = context.getInboundMessageIssuer();

        // requestMessage == null is checked
        SignableSAMLObject message = context.getInboundSAMLMessage();
                
        if (_idpStorageManager.existStorage(sIssuer))
        {
            _logger.debug("No IDP found with for issuer: " + sIssuer);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        SAML2IDP saml2IDP = (SAML2IDP)_idpStorageManager.getIDP(sIssuer);
           
        //Validate signature  
        HTTPInTransport inTransport = (HTTPInTransport) context.getInboundMessageTransport();
        String sigParam = inTransport.getParameterValue("Signature");
        boolean bSignatureParam = !DatatypeHelper.isEmpty(sigParam);
        if(bSignatureParam || message.isSigned())
        {           
            if (!validateSignature(context, saml2IDP, sIssuer))
            {
                _logger.debug("Invalid XML signature received for message from issuer: " + sIssuer);
                throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
            }     
            
            _logger.debug("XML signature validation okay");
            
        }
        
        return saml2IDP;
    }
}
