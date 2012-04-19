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
package com.alfaariss.oa.util.saml2.opensaml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.security.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xml.signature.SignatureConstants;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;

/**
 * Custom OpenSAML SecurityConfigurationBootstrap.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.2
 */
public class CustomOpenSAMLSecurityConfigurationBootstrap extends DefaultSecurityConfigurationBootstrap
{   
    /**
     * Build and return a default configuration.
     * 
     * @return a new basic security configuration with reasonable default values
     */
    public static BasicSecurityConfiguration buildDefaultConfig() 
    {
        BasicSecurityConfiguration config = new BasicSecurityConfiguration();
        
        populateSignatureParams(config);
        populateEncryptionParams(config);
        populateKeyInfoCredentialResolverParams(config);
        populateKeyInfoGeneratorManager(config);
        populateKeyParams(config);
        
        return config;
    }

    
    /**
     * Populate signature-related parameters.
     * 
     * @param config the security configuration to populate
     */
    protected static void populateSignatureParams(BasicSecurityConfiguration config) 
    {   
        Log logger = LogFactory.getLog(CustomOpenSAMLSecurityConfigurationBootstrap.class);
        CryptoManager cryptoManager = Engine.getInstance().getCryptoManager();
        String sSignatureAlgorithmURI =  SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
        String sMessageDigestAlgorithmURI = SignatureConstants.ALGO_ID_DIGEST_SHA1;
        
        try
        {
            sSignatureAlgorithmURI = SAML2CryptoUtils.getXMLSignatureURI(cryptoManager);
        }
        catch (OAException e)
        {   
            logger.warn("Could not resolve signature algorithm from OA Crypto configuration, using default: " 
                + sSignatureAlgorithmURI);
        }
        
        try
        {
            sMessageDigestAlgorithmURI = SAML2CryptoUtils.getXMLDigestMethodURI(cryptoManager.getMessageDigest());
        }
        catch (OAException e)
        {   
            logger.warn("Could not resolve digest algorithm from OA Crypto configuration, using default: " 
                + sMessageDigestAlgorithmURI);
        }
        
        // Asymmetric key algorithms
        config.registerSignatureAlgorithmURI("RSA", sSignatureAlgorithmURI);
        config.registerSignatureAlgorithmURI("DSA", SignatureConstants.ALGO_ID_SIGNATURE_DSA);
        config.registerSignatureAlgorithmURI("ECDSA", SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1);
        
        // HMAC algorithms
        config.registerSignatureAlgorithmURI("AES", SignatureConstants.ALGO_ID_MAC_HMAC_SHA1);
        config.registerSignatureAlgorithmURI("DESede", SignatureConstants.ALGO_ID_MAC_HMAC_SHA1);
        
        // Other signature-related params
        config.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        config.setSignatureHMACOutputLength(null);
        config.setSignatureReferenceDigestMethod(sMessageDigestAlgorithmURI);
    }
}
