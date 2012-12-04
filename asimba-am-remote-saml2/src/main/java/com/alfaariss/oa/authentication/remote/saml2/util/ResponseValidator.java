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
package com.alfaariss.oa.authentication.remote.saml2.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.security.SAML2HTTPPostSimpleSignRule;
import org.opensaml.saml2.binding.security.SAML2HTTPRedirectDeflateSignatureRule;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.ChainingCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.StaticCredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.validation.ValidationException;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoException;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.util.saml2.SAML2SecurityException;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;

/**
 * Utility class to enable SAML response verification. Verification methods in this class
 * are copied directly from AbstractSAML2Profile because the use of a requestor profile class
 * is not permitted here.
 *
 * TODO -MG: remove when this functionality is moved from AbstractSAML2Profile to separate class.
 *
 * @author MHO
 * @author jre
 * @author Alfa & Ariss
 * 
 * @see com.alfaariss.oa.util.saml2.profile.AbstractSAML2Profile
 */
public class ResponseValidator
{
    private Log _logger = null;
    private Credential _credential = null;
    private CryptoManager _cryptoManager = null;
    private SAML2IDP _organization = null;
    private KeyInfoCredentialResolver _keyInfoCredResolver = null;
    private SAMLSignatureProfileValidator _profileValidator = null;
    private BasicParserPool _pool = null;
    
    private ChainingCredentialResolver _chainingCredentialResolver = null;
    private SignatureTrustEngine _sigTrustEngine = null;
    private String _sEntityID;
    private String _issuer;
    
    private boolean _signatureRequired = false;
    
    /**
     * default constructor
     * 
     * @param sEntityID The Entity ID of the OA server. 
     * @param organization The object containing organization information.
     * @param requireSignature Indicates if a signature is mandatory
     */
    public ResponseValidator(String sEntityID, SAML2IDP organization, boolean requireSignature)
    {
        _logger = LogFactory.getLog(ResponseValidator.class);
        
        Engine engine = Engine.getInstance();
        _cryptoManager = engine.getCryptoManager();
        
        _sEntityID = sEntityID;
        _organization = organization;
        _signatureRequired = requireSignature;
        
        try
        {
            _credential = SAML2CryptoUtils.retrieveMySigningCredentials(
                _cryptoManager, _sEntityID);
        }
        catch(OAException e)
        {          
           //Logged in SAML2CryptoUtils
        }
        
        _keyInfoCredResolver =
            Configuration.getGlobalSecurityConfiguration(
                ).getDefaultKeyInfoCredentialResolver();
        
        _profileValidator = new SAMLSignatureProfileValidator();
        
        _pool = new BasicParserPool();
        _pool.setNamespaceAware(true);
        
        //Create ChainingCredentialResolver
        _chainingCredentialResolver =  
            new ChainingCredentialResolver();           
           
        //TODO -MG: EVB, JRE, RDV: define order of credential resolvers and test
                     
        //Metadata credentials
        if(_organization != null)
        {
            _issuer = _organization.getID();
            MetadataProvider mdProvider= null;
            try
            {
                mdProvider = _organization.getMetadataProvider();
            }
            catch (OAException e)
            {
                _logger.debug(
                    "Could not resolve Metadata provider found for issuer: " + _issuer);
            }
            
            if(mdProvider != null) //Metadata provider available
            {
                _logger.debug(
                    "Metadata provider found for issuer: " + _issuer);
                MetadataCredentialResolver mdCredResolver = 
                    new MetadataCredentialResolver(mdProvider);
                _chainingCredentialResolver.getResolverChain().add(mdCredResolver);
            }
        }
        
        //OA Engine credentials
        try
        {               
            if(_credential != null) //OA Signing enabled
            {
                Credential signingCred = 
                    SAML2CryptoUtils.retrieveSigningCredentials(
                        _cryptoManager, _issuer);                   
                StaticCredentialResolver oaResolver = 
                    new StaticCredentialResolver(signingCred);
                _chainingCredentialResolver.getResolverChain().add(oaResolver);
            }
        }
        catch(CryptoException e) //No certificate found
        {
            _logger.debug(
                "No trusted certificate found for issuer: " + _issuer);
            //Ignore
        }
        
        _sigTrustEngine = 
            new ExplicitKeySignatureTrustEngine(
                _chainingCredentialResolver, _keyInfoCredResolver);
    }
    
    /**
     * Validate the decoded SAML2 response message.
     *
     * Performs basic message verification:  
     * <dl>
     *  <dd>{@link #validateSignature(SAMLMessageContext)}
     *  </dd>
     *      <dt>Validate signature</dt>
     *  <dd>Mandatory signing verification</dd>
     *      <dt>Verify if request MUST be signed</dt>
     * <dl>     
     * 
     * @param context The message context containing decoded message
     * @throws SAML2SecurityException If message should be rejected.
     * @throws OAException If an internal error occurs
     */
    public void validateResponse(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context) 
        throws SAML2SecurityException, OAException
    {        
        context.setPeerEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        validateMessage(context);
    }
    
    /**
     * Validates a SAML object.
     * 
     * @param context Message context.
     * @param obj The SAML object
     * @return true if not signed or if signature is correct.
     * @throws OAException If security error occurs
     */
    public boolean validateMessage(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context, SignableSAMLObject obj)
    throws OAException
    {
        boolean bValid = false;
        
        Signature signature = obj.getSignature();
        
        if(obj.isSigned()) //Validate XML signature (if applicable)
        {    
            //create criteria set            
            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(new EntityIDCriteria(_issuer));
            MetadataCriteria mdCriteria = new MetadataCriteria(
                context.getPeerEntityRole(), 
                context.getInboundSAMLProtocol());
            criteriaSet.add(mdCriteria);
            criteriaSet.add(new UsageCriteria(UsageType.SIGNING) );
            try
            {
                bValid = _sigTrustEngine.validate(signature, criteriaSet);
            }
            catch (SecurityException e) //Internal processing error
            {
                _logger.error("Processing error evaluating the signature", e);           
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }   
        else
            bValid = !_signatureRequired; //Message itself not signed
        
        return bValid;
    }
    
    /**
     * Validate a inbound message signature and/or simple signature.
     * @param context The message context.
     * @return <code>true</code> if signature is valid, otherwise <code>false</code>. 
     * @throws OAException If validation fails due to internal error.
     */
    protected boolean validateSignature( SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context) throws OAException 
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
            
            //TODO -MG: EVB, JRE, RDV: define order of credential resolvers and test                        
            if(_chainingCredentialResolver.getResolverChain().isEmpty())
            {
                _logger.warn(
                    "No trusted certificate or metadata found for issuer: " + _issuer);
                //bValid = false already    
            }
            else
            {               
                //Create trust engine                
                //TODO -MG: EVB: trust engine and resolver creation can be placed in one-time init code (e.g. SAML2Requestor)
                
                bValid = validateMessage(context, message);
                
                if(bValid) //Message not signed or valid signature
                {
                    //Validate simple signature for GET (if applicable)
                    SAML2HTTPRedirectDeflateSignatureRule ruleGET = 
                        new SAML2HTTPRedirectDeflateSignatureRule(_sigTrustEngine);
                    ruleGET.evaluate(context);
                    //Validate simple signature for POST (if applicable)
                    SAML2HTTPPostSimpleSignRule rulePOST = 
                        new SAML2HTTPPostSimpleSignRule(_sigTrustEngine, 
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
        return bValid;
    }

    // Validate the decoded SAML2 message.     
    private void validateMessage(SAMLMessageContext<SignableSAMLObject, 
        SignableSAMLObject, SAMLObject> context) 
        throws SAML2SecurityException, OAException
    {        
        // requestMessage == null is checked
        SignableSAMLObject message = context.getInboundSAMLMessage();
        
        //Validate requestor
        String sRequestor = context.getInboundMessageIssuer();
        
        //DD We are aware of the fact that AuthZQuery responses MUST contain Issuer
        //Not SAML correct!
        if (sRequestor == null) sRequestor = _organization.getID();                  
            
        //Validate signature
        String sigParam = null;
        HTTPInTransport inTransport = (HTTPInTransport) context.getInboundMessageTransport();
        if (inTransport != null)
            sigParam = inTransport.getParameterValue("Signature");
        
        boolean bSignatureParam = !DatatypeHelper.isEmpty(sigParam);
        if(bSignatureParam || message.isSigned())
        {           
            if (!validateSignature(context))
            {
                _logger.debug("Invalid XML signature received for message");
                throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
            }     
            
            _logger.debug("XML signature validation okay");
            
        }
        else if (_signatureRequired)
        {
            //no signature, but was required: error:
            _logger.debug("No signature received for message, which is required");
            throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
        }
    }
}
