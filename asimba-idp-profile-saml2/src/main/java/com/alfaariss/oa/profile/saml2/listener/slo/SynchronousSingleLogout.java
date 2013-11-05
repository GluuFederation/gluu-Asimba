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
package com.alfaariss.oa.profile.saml2.listener.slo;

import java.security.NoSuchAlgorithmException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.binding.security.SAML2HTTPPostSimpleSignRule;
import org.opensaml.saml2.binding.security.SAML2HTTPRedirectDeflateSignatureRule;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.impl.BodyBuilder;
import org.opensaml.ws.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.ChainingCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.StaticCredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.attribute.ITGTAttributes;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoException;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.profile.saml2.profile.sso.WebBrowserSSO;
import com.alfaariss.oa.util.saml2.NameIDFormatter;
import com.alfaariss.oa.util.saml2.SAML2Requestor;
import com.alfaariss.oa.util.saml2.SAML2SecurityException;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;

/**
 * Performs logout requests.
 * <br>
 * Synchronous and asynchronous logout requests are supported.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.0
 */
public class SynchronousSingleLogout
{    
    private static Log _logger;
    private XMLObjectBuilderFactory _builderFactory;
    private CryptoManager _cryptoManager;
    private EntityDescriptor _entityDescriptor;
    private NameIDFormatter _nameIDFormatter;
    private Credential _credential;
    private SAMLSignatureProfileValidator _profileValidator;
    private KeyInfoCredentialResolver _keyInfoCredResolver;
    private BasicParserPool _parserPool;
    
    /**
     * Default constructor. 
     * @param entityDescriptor EntityDescriptor of this IDP
     * @throws OAException If an internal error ocurred.
     */
    public SynchronousSingleLogout(EntityDescriptor entityDescriptor) 
        throws OAException
    {
        _logger = LogFactory.getLog(SynchronousSingleLogout.class);
        _entityDescriptor = entityDescriptor;
        _builderFactory = Configuration.getBuilderFactory();
        
        Engine oaEngine = Engine.getInstance();
        _cryptoManager = oaEngine.getCryptoManager();
        
        _nameIDFormatter = new NameIDFormatter(_cryptoManager, 
            oaEngine.getTGTFactory().getAliasStoreSP());
        
        _profileValidator = new SAMLSignatureProfileValidator();
        
        //TODO EVB, MHO: DefaultKeyInfoCredentialResolver sufficient?
        _keyInfoCredResolver =
            Configuration.getGlobalSecurityConfiguration(
                ).getDefaultKeyInfoCredentialResolver();
        
        try
        {
            _credential = SAML2CryptoUtils.retrieveMySigningCredentials(
                _cryptoManager, _entityDescriptor.getEntityID());
        }
        catch(OAException e)
        {          
           //Logged in SAML2CryptoUtils
        } 
        
        _parserPool = new BasicParserPool();
        _parserPool.setNamespaceAware(true);
    }
    
    /**
     * Performs asynchronous logout.
     * <br>
     * Uses the SAMLConstants.SAML2_SOAP11_BINDING_URI to logout.
     * 
     * @param user The user to be loggedout. 
     * @param saml2Requestor The requestor were to logout.
     * @param slService SingleLogoutService
     * @param reason The optional reason (can be null)
     * @param attributes TGT attributes object.
     * @param sSessionIndex The sessionIndex to logout
     * @param tgtID The TGT ID.
     * @return UserEvent The result of the logout.
     */
    public UserEvent processSynchronous(IUser user, SAML2Requestor saml2Requestor, 
        SingleLogoutService slService, String reason, ITGTAttributes attributes, 
        String sSessionIndex, String tgtID)
    {
        try
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
                    attributes, sSessionIndex, tgtID, saml2Requestor.getID());
                        
            String location = slService.getLocation();
            
            _logger.debug("Sending synchronous logout request to location: " + location);

            StatusResponseType logoutResponse = (StatusResponseType)sendSOAPMessage(location, logoutRequest);
            if (logoutResponse == null)
            {
                _logger.warn("No logout response from: " + location);
                throw new MessageEncodingException("No response recieved");
            }
            
            SAMLMessageContext<SignableSAMLObject,SignableSAMLObject,SAMLObject> 
                samlContext = new BasicSAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject>();
            samlContext.setInboundSAMLMessage(logoutResponse);
            samlContext.setInboundMessageIssuer(saml2Requestor.getID());
            
            return verifyResponse(samlContext, saml2Requestor);
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
            logXML(request);
        
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
   
    private UserEvent verifyResponse(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context, SAML2Requestor saml2Requestor)
        throws OAException
    {
        try
        {   
            StatusResponseType resp = (StatusResponseType)context.getInboundSAMLMessage();
                        
            context.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
            
            validateMessage(context, saml2Requestor);
            
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

    private LogoutRequest buildLogoutRequest(String sID, IUser user, 
        String reason, ITGTAttributes attributes, String sSessionIndex,
        String tgtID, String requestorID) throws OAException, SecurityException
    {
        LogoutRequestBuilder lrBuilder = 
            (LogoutRequestBuilder)_builderFactory.getBuilder(
                LogoutRequest.DEFAULT_ELEMENT_NAME);
        
        LogoutRequest logoutRequest = lrBuilder.buildObject();
        
        logoutRequest.setID(sID);
        
        //TODO add support for multiple session indexes
        SessionIndexBuilder sessionIndexBuilder = 
            (SessionIndexBuilder)_builderFactory.getBuilder(
                SessionIndex.DEFAULT_ELEMENT_NAME);
        SessionIndex sessionIndex = sessionIndexBuilder.buildObject();
        sessionIndex.setSessionIndex(sSessionIndex);
        logoutRequest.getSessionIndexes().add(sessionIndex);
        
        String sNameQualifier = _entityDescriptor.getEntityID();
        
        String sNameIDFormat = (String)attributes.get(WebBrowserSSO.class, 
            WebBrowserSSO.TGT_REQUEST_NAMEIDFORMAT);
        
        String sSPNameQualifier = (String)attributes.get(WebBrowserSSO.class, 
            WebBrowserSSO.TGT_REQUEST_SPNAMEQUALIFIER);
        
        String sNameID = _nameIDFormatter.resolve(sNameIDFormat, requestorID, tgtID);
        if (sNameID == null)
        {
            StringBuffer sbDebug = new StringBuffer("No NameID found with format '");
            sbDebug.append(sNameIDFormat);
            sbDebug.append("' for requestor: ");
            sbDebug.append(requestorID);
            _logger.debug(sbDebug.toString());
            sNameID = user.getID();
            sNameIDFormat = null;
        }
        
        NameID nid = buildNameID(sNameID, sNameIDFormat, sNameQualifier, sSPNameQualifier);
        logoutRequest.setNameID(nid);
        
        logoutRequest.setReason(reason);
        logoutRequest.setVersion(SAMLVersion.VERSION_20);
        logoutRequest.setIssueInstant(new DateTime());
        
        Issuer issuer = buildIssuer(null, _entityDescriptor.getEntityID());
        logoutRequest.setIssuer(issuer);
        
        if (_cryptoManager.getPrivateKey() != null)
        {
            Signature signature = createSignature();
            logoutRequest.setSignature(signature);
            
            //update digest algorithm
            SAMLObjectContentReference contentReference = 
                ((SAMLObjectContentReference)signature.getContentReferences().get(0));
            contentReference.setDigestAlgorithm(
                SAML2CryptoUtils.getXMLDigestMethodURI(_cryptoManager.getMessageDigest()));
            
            signXMLObject(logoutRequest, signature);
        }
        
        return logoutRequest;
    }
    
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
    
    private NameID buildNameID(String sNameID, String sFormat, 
        String sNameQualifier, String sSPNameQualifier)
    {
        NameIDBuilder nameidBuilder = 
            (NameIDBuilder)_builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        
        NameID nid = nameidBuilder.buildObject();
        
        nid.setValue(sNameID);

        //TODO (MHO) maybe set the nid.setSPProvidedID(?);
        
        if (sFormat != null)
            nid.setFormat(sFormat);
        
        if (sNameQualifier != null)
            nid.setNameQualifier(sNameQualifier);
        
        if (sSPNameQualifier != null)
            nid.setSPNameQualifier(sSPNameQualifier);
        
        return nid;
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
                _cryptoManager, _entityDescriptor.getEntityID());                         
        signature.setSigningCredential(signingX509Cred);

        SecurityHelper.prepareSignatureParams(
            signature, signingX509Cred, null, null);
        
        return signature;
    }
    
    private void signXMLObject(XMLObject obj, Signature signature) throws OAException
    {        
        try
        {           
            //Marshall 
            Marshaller marshaller = Configuration.getMarshallerFactory(
                ).getMarshaller(obj);
            if (marshaller == null) 
            {
                _logger.error("No marshaller registered for " + 
                    obj.getElementQName() + 
                    ", unable to marshall assertion");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            if(obj.getDOM() == null)
                marshaller.marshall(obj);
            
            Signer.signObject(signature);
        }
        catch (OAException e) 
        {
             throw e;
        }
        catch (MarshallingException e)
        {
            _logger.warn(
                "Marshalling error while signing object", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch(Exception e)
        {
            _logger.error("Could not sign object", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    // Validate the decoded SAML2 message.     
    private void validateMessage(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context, SAML2Requestor requestor) 
        throws SAML2SecurityException, OAException
    {        
        // requestMessage == null is checked
        SignableSAMLObject message = context.getInboundSAMLMessage();
        
        //Validate signature  
        String sigParam = null;
        HTTPInTransport inTransport = (HTTPInTransport) context.getInboundMessageTransport();
        if (inTransport != null)
            sigParam = inTransport.getParameterValue("Signature");
            
        if(!DatatypeHelper.isEmpty(sigParam) || message.isSigned())
        {
            String issuer = context.getInboundMessageIssuer();
            
            if (!validateSignature(context, requestor.getMetadataProvider(), issuer))
            {
                _logger.debug("Invalid XML signature received for message from issuer: " + issuer);
                throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
            }     
            
            _logger.debug("XML signature validation okay");
        }
    }
    
    /**
     * Validate a inbound message signature and/or simple signature.
     * @param context The message context.
     * @param requestor The requestor. 
     * @param issuer The inbound message issuer
     * @return <code>true</code> if signature is valid, otherwise <code>false</code>. 
     * @throws OAException If validation fails due to internal error.
     */
    private boolean validateSignature(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context, MetadataProvider metadataProvider, String issuer) throws OAException 
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
            if(metadataProvider != null)
            {
                _logger.debug("Metadata provider found for issuer: " + issuer);
                MetadataCredentialResolver mdCredResolver = 
                    new MetadataCredentialResolver(metadataProvider);
                chainingCredentialResolver.getResolverChain().add(mdCredResolver);
            }
            
            //OA Engine credentials
            try
            {               
                if(_credential != null) //OA Signing enabled
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
                            _parserPool, _keyInfoCredResolver);
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
    
    /**
     * Caller should perform debug enabled check
     * Logs the XML object as debug logging. 
     * @param xmlObject The XML object that must be logged.
     */
    private void logXML(XMLObject xmlObject)
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
                    marshaller.marshall(xmlObject);
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
            _logger.info(sXML);
        }
    }
}
