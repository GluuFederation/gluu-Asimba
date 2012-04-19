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
package com.alfaariss.oa.util.saml2.profile;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.binding.security.SAML2HTTPPostSimpleSignRule;
import org.opensaml.saml2.binding.security.SAML2HTTPRedirectDeflateSignatureRule;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
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
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoException;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.SAML2Requestor;
import com.alfaariss.oa.util.saml2.SAML2Requestors;
import com.alfaariss.oa.util.saml2.SAML2SecurityException;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;

/**
 * Abstract SAML2 profile implementation.
 *
 * @author MHO
 * @author Alfa & Ariss
 */
public abstract class AbstractSAML2Profile implements ISAML2Profile, IAuthority
{
    /** Profile id */
    protected String _sID;
    /** OA Profile ID */
    protected String _sOAProfileID;
    /** Session factory */
    protected ISessionFactory _sessionFactory;
    /** requestor pool factory */
    protected IRequestorPoolFactory _requestorPoolFactory;
    /** crypto manager */
    protected CryptoManager _cryptoManager;
    /** TGT factory */
    protected ITGTFactory _tgtFactory;
    /** Entity ID to be used in response */
    protected String _sEntityID;
    /** URL to the SAML profile */
    protected String _sProfileURL;
    /** Event logger */
    protected Log _eventLogger;
    /** Path to the OA WebSSO profile*/
    protected String _sWebSSOPath;
    /** EntityDescriptor */
    protected EntityDescriptor _entityDescriptor;
    /** Requestors object */
    protected SAML2Requestors _requestors;
    /** Signing is enabled in OA */
    protected boolean _signingEnabled;
    /** IssueInstant accept window object */
    protected SAML2IssueInstantWindow _issueInstantWindow;
    /** The XML parser pool */
    protected BasicParserPool _pool;
    /** SAMLSignatureProfileValidator */
    protected SAMLSignatureProfileValidator _profileValidator;
    /** KeyInfoCredentialResolver */
    protected KeyInfoCredentialResolver _keyInfoCredResolver;
                   
    private final static String AUTHORITY_NAME = "SAML2 Profile";
    
    private Log _logger;
    
    /**
     * @see com.alfaariss.oa.util.saml2.profile.ISAML2Profile#init(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element, org.opensaml.saml2.metadata.EntityDescriptor, java.lang.String, java.lang.String, com.alfaariss.oa.util.saml2.SAML2Requestors, com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow, java.lang.String)
     */
    public void init(IConfigurationManager configurationManager,
        Element config, EntityDescriptor entityDescriptor, 
        String sBaseUrl, String sWebSSOPath, SAML2Requestors requestors, 
        SAML2IssueInstantWindow issueInstantWindow, String sProfileID) 
        throws OAException
    {
        try
        {
            _logger = LogFactory.getLog(this.getClass());
            _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
            _profileValidator = new SAMLSignatureProfileValidator();
            _pool = new BasicParserPool();
            _pool.setNamespaceAware(true); 
            
            //TODO EVB, MHO: DefaultKeyInfoCredentialResolver sufficient?
            _keyInfoCredResolver =
                Configuration.getGlobalSecurityConfiguration(
                    ).getDefaultKeyInfoCredentialResolver();
            
            _entityDescriptor = entityDescriptor;
            _sWebSSOPath = sWebSSOPath;
            _requestors = requestors;
            _issueInstantWindow = issueInstantWindow;
            _sOAProfileID = sProfileID;
            _sEntityID = _entityDescriptor.getEntityID();
            
            Engine engine = Engine.getInstance();
            _sessionFactory = engine.getSessionFactory();
            _tgtFactory = engine.getTGTFactory();
            _requestorPoolFactory = engine.getRequestorPoolFactory();
            _cryptoManager = engine.getCryptoManager();
            
            _sID = configurationManager.getParam(config, "id");
            if (_sID == null)
            {
                _logger.error("No 'id' item found in 'profile' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //create profile url
            StringBuffer sbProfileURL = new StringBuffer(sBaseUrl);
            if (!sBaseUrl.endsWith("/"))
                sbProfileURL.append("/");
            sbProfileURL.append(_sID);
            _sProfileURL = sbProfileURL.toString();
            
            try
            {
                _signingEnabled = false;
                SAML2CryptoUtils.retrieveMySigningCredentials(_cryptoManager, _sEntityID);
                SAML2CryptoUtils.getXMLSignatureURI(_cryptoManager);
                SAML2CryptoUtils.getXMLDigestMethodURI(_cryptoManager.getMessageDigest());
                _signingEnabled = true;
                _logger.info("Signing enabled");
            }
            catch(OAException e)
            {          
                //Logged in SAML2CryptoUtils
                _logger.info("Signing disabled");
            }           
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during initialize", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        } 
    }
    
    /**
     * @see ISAML2Profile#destroy()
     */
    public void destroy()
    {
        
    }

    /**
     * @see com.alfaariss.oa.util.saml2.profile.ISAML2Profile#getID()
     */
    public String getID()
    {
        return _sID;
    }
    

    /**
     * @see com.alfaariss.oa.api.logging.IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME;
    }
    
    /**
     * Returns the URL to this profile.
     * 
     * @return The URL as String.
     */
    protected String getProfileURL()
    {
        return _sProfileURL;
    }
    
    /**
     * Build an endpoint.
     * 
     * @param elementName The type of service for the endpoint.
     * @param sBinding The binding to be used.
     * @param sLocation The endpoint location.
     * @param sResponseLocation The optional response location. 
     * @return The constructed endpoint.
     */
    protected Endpoint buildMetadataEndpoint(QName elementName, 
        String sBinding, String sLocation, 
        String sResponseLocation)
    {
        XMLObjectBuilderFactory builderFactory = 
            Configuration.getBuilderFactory();
        
        XMLObjectBuilder endpointBuilder = builderFactory.getBuilder(elementName);
            
        Endpoint samlEndpoint = (Endpoint)endpointBuilder.buildObject(elementName);
        samlEndpoint.setLocation(sLocation);
        samlEndpoint.setBinding(sBinding);
        
        if (sResponseLocation != null)
            samlEndpoint.setResponseLocation(sResponseLocation);  
        
        return samlEndpoint;
    }
    
    /**
     * Sign the suplied saml object.
     * @param samlObject saml object to be signed
     * @throws OAException If the crypto configuration in OA is unsupported
     */
    protected void signSAMLObject(SignableSAMLObject samlObject) 
        throws OAException
    {
        try
        {  
            XMLObjectBuilderFactory builderFactory = 
                Configuration.getBuilderFactory();
            //Build signature
            SignatureBuilder builder = 
                (SignatureBuilder)builderFactory.getBuilder(
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
            
            samlObject.setSignature(signature);
            
            //update digest algorithm
            SAMLObjectContentReference contentReference = 
                ((SAMLObjectContentReference)signature.getContentReferences().get(0));
            contentReference.setDigestAlgorithm(
                SAML2CryptoUtils.getXMLDigestMethodURI(_cryptoManager.getMessageDigest()));
            
            //Marshall 
            Marshaller marshaller = Configuration.getMarshallerFactory(
                ).getMarshaller(samlObject);
            if (marshaller == null) 
            {
                _logger.error("No marshaller registered for " + 
                    samlObject.getElementQName() + 
                    ", unable to marshall assertion");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            if(samlObject.getDOM() == null)
                marshaller.marshall(samlObject);
            
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
    
    /**
     * Forwards the user to the OA WebSSO Servlet.
     * <br>
     * Before forwarding the session.setProfileURL() is set and the session is 
     * added as an attribute in the request .
     * @param request The servlet request.
     * @param response The servlet response.
     * @param session The user session
     * @throws OAException If the user can't be forwarded.
     */
    protected void forwardUser(HttpServletRequest request,
        HttpServletResponse response, ISession session) 
        throws OAException
    {
        try
        {
            StringBuffer sbProfileUrl = new StringBuffer();
            sbProfileUrl.append(_sProfileURL);
            sbProfileUrl.append("?");
            sbProfileUrl.append(ISession.ID_NAME);
            sbProfileUrl.append("=");
            sbProfileUrl.append(session.getId());
    
            session.setProfileURL(sbProfileUrl.toString());
            
            request.setAttribute(ISession.ID_NAME, session);
            
            RequestDispatcher oDispatcher = request.getRequestDispatcher(
                _sWebSSOPath);
            if(oDispatcher == null)
            {
                _logger.warn(
                    "There is no requestor dispatcher supported with name: " 
                    + _sWebSSOPath);                    
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            oDispatcher.forward(request, response);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not forward user", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Caller should perform debug enabled check
     * Logs the XML object as debug logging. 
     * @param xmlObject The XML object that must be logged.
     */
    protected void logXML(XMLObject xmlObject)
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
                    eDOM = marshaller.marshall(xmlObject);
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
            _logger.debug(sXML);
        }
        
    }
    
    /**
     * Creates a default empty SAML context object.
     *  
     * @param request Servlet request.
     * @param response Servlet response.
     * @return Default SAML context object.
     */
    protected SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
        createEncodingContext(HttpServletRequest request, 
            HttpServletResponse response)
    {
        HTTPInTransport inTransport = new HttpServletRequestAdapter(request);
                
        HTTPOutTransport outTransport = new HttpServletResponseAdapter(response, 
            request.isSecure());
        
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
            context = new BasicSAMLMessageContext<SignableSAMLObject, 
                SignableSAMLObject, SAMLObject>();  
        
        context.setInboundMessageTransport(inTransport);
        context.setOutboundMessageTransport(outTransport);
        
        return context;
    }
    
    /**
     * Validate the decoded SAML2 request message.
     *
     * Performs basic message verification:  
     * <dl>
     *  <dd>{@link AbstractSAML2Profile#validateRequestor(String)}</dd>
     *      <dt>Validate requestor</dt>
     *  <dd>{@link AbstractSAML2Profile#validateSignature(SAMLMessageContext, 
     *      SAML2Requestor, String)}
     *  </dd>
     *      <dt>Validate signature</dt>
     *  <dd>Mandatory signing verification</dd>
     *      <dt>Verify if request MUST be signed</dt>
     * <dl>     
     * 
     * @param context The message context containing decoded message
     * @param role The peer entity role.
     * @return SAML2Requestor if available, else <code>null</code>.
     * @throws SAML2SecurityException If message should be rejected.
     * @throws OAException If an internal error occurs
     */
    protected SAML2Requestor validateRequest(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context, QName role) 
        throws SAML2SecurityException, OAException
    {   
        context.setPeerEntityRole(role);       
        String sIssuer = context.getInboundMessageIssuer();
        return validateMessage(context, sIssuer);  
    }
    
    /**
     * Validate the decoded SAML2 response message.
     *
     * Performs basic message verification:  
     * <dl>
     *  <dd>{@link AbstractSAML2Profile#validateRequestor(String)}</dd>
     *      <dt>Validate requestor</dt>
     *  <dd>{@link AbstractSAML2Profile#validateSignature(SAMLMessageContext, 
     *      SAML2Requestor, String)}
     *  </dd>
     *      <dt>Validate signature</dt>
     *  <dd>Mandatory signing verification</dd>
     *      <dt>Verify if request MUST be signed</dt>
     * <dl>     
     * 
     * @param context The message context containing decoded message
     * @param role The peer entity role.
     * @return SAML2Requestor if available, else <code>null</code>.
     * @throws SAML2SecurityException If message should be rejected.
     * @throws OAException If an internal error occurs
     */
    protected SAML2Requestor validateResponse(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context, QName role) 
        throws SAML2SecurityException, OAException
    {        
        context.setPeerEntityRole(role);       
        String sIssuer = context.getInboundMessageIssuer();
        return validateMessage(context, sIssuer);         
    }
    
    /**
     * Business rule and profile validation of the issuer.
     *
     * @param sRequestorID The inbound issuer.
     * @return The requestor object.
     * @throws SAML2SecurityException If the requestor is invalid.
     * @throws OAException If validation fails due to internal error.
     */
    protected IRequestor validateRequestor(
        String sRequestorID) throws SAML2SecurityException, OAException
    {
        if(sRequestorID == null)
        {           
            _logger.debug("Missing issuer");
            throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID); 
        }          
    
        IRequestor oRequestor = _requestorPoolFactory.getRequestor(sRequestorID);
        if (oRequestor == null)
        {
            StringBuffer sbError = new StringBuffer(
                "Unknown requestor found in request: ");
            sbError.append(sRequestorID);
            _logger.debug(sbError.toString());
            throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);                    
        }
        
        if (!oRequestor.isEnabled())
        {
            _logger.debug("Disabled requestor found in request: " 
                + sRequestorID);
            throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID); 
        }
        
        RequestorPool oRequestorPool = 
            _requestorPoolFactory.getRequestorPool(oRequestor.getID());
        if (oRequestorPool == null)
        {
            _logger.warn("Requestor not available in a pool: " 
                + oRequestor.getID());
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    
        if (!oRequestorPool.isEnabled())
        {
            StringBuffer sbError = new StringBuffer("Requestor '");
            sbError.append(oRequestor.getID());
            sbError.append("' is found in a disabled requestor pool: ");
            sbError.append(oRequestorPool.getID());
            _logger.warn(sbError.toString());
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return oRequestor;
    }
    
    /**
     * Validate a inbound message signature and/or simple signature.
     * @param context The message context.
     * @param requestor The requestor. 
     * @param issuer The inbound message issuer
     * @return <code>true</code> if signature is valid, otherwise <code>false</code>. 
     * @throws OAException If validation fails due to internal error.
     */
    protected boolean validateSignature( SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context,
        SAML2Requestor requestor, String issuer) throws OAException 
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
            if(requestor != null)
            {
                MetadataProvider mdProvider = 
                    requestor.getChainingMetadataProvider();
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

    // Validate the decoded SAML2 message.     
    private SAML2Requestor validateMessage(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context, String issuer) 
        throws SAML2SecurityException, OAException
    {        
        // requestMessage == null is checked
        SignableSAMLObject message = context.getInboundSAMLMessage();
        
        //Validate requestor
        IRequestor oaRequestor = validateRequestor(issuer);
        
        //Retrieve requestor info
        boolean mandatorySigning = _requestors.isDefaultSigningEnabled();
        SAML2Requestor requestor = _requestors.getRequestor(oaRequestor);
        if(requestor != null)
            mandatorySigning = requestor.isSigningEnabled();                          
            
        //Validate signature  
        HTTPInTransport inTransport = (HTTPInTransport) context.getInboundMessageTransport();
        String sigParam = inTransport.getParameterValue("Signature");
        boolean bSignatureParam = !DatatypeHelper.isEmpty(sigParam);
        if(bSignatureParam || message.isSigned())
        {           
			if (!validateSignature(context, requestor, issuer))
            {
            	_logger.debug("Invalid XML signature received for message from issuer: " + issuer);
                throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
            }     
			
			_logger.debug("XML signature validation okay");
			
        }
        else if (mandatorySigning) //Verify mandatory signing
        {
            _logger
                .debug("No mandatory signature received from issuer: " + issuer);
            throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
        }
        
        return requestor;
    }
}
