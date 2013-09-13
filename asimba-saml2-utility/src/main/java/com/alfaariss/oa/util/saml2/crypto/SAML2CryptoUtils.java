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
package com.alfaariss.oa.util.saml2.crypto;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignatureConstants;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.engine.core.crypto.CryptoException;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;

/**
 * OA specific SAML2 crypto utilities.
 *
 * @author EVB
 * @author Alfa & Ariss
 */
public class SAML2CryptoUtils
{
    private static Log _logger = LogFactory.getLog(SAML2CryptoUtils.class);
    
    /**
     * Retrieve the XML Signature specification URI based on OA Crypto.
     *
     * @param crypto The OA crypto manager.
     * @return  The SAML2 signature URI
     * @throws OAException If OA signing is disabled or protocol is invalid.
     * @see SignatureConstants
     */
    public static String getXMLSignatureURI(CryptoManager crypto) throws OAException
    {
        String sUri = null;
        Signature signature = crypto.getSignature();
        if(signature == null)
        {    
            _logger.warn("OA Signing is disabled");
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }

        String algorithm = signature.getAlgorithm();
        if("SHA1withRSA".equals(algorithm))
        {
            sUri = SignatureConstants.ALGO_ID_SIGNATURE_RSA;  
        }
        else if("SHA1withDSA".equals(algorithm))
        {
            sUri = SignatureConstants.ALGO_ID_SIGNATURE_DSA; 
        }
        else if("SHA256withRSA".equals(algorithm))
        {
            sUri = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
        }
        else if("SHA384withRSA".equals(algorithm))
        {
            sUri = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384;
        }
        else if("SHA512withRSA".equals(algorithm))
        {
            sUri = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512;
        }
        else if("MD5withRSA".equals(algorithm))
        {
            sUri = SignatureConstants.ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5;
        }
        else
        {
            //DD Only a limited number of signing algorithms are supported in OA SAML2
            _logger.error(
                "Unsupported digital signature algorithm: " + algorithm);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return sUri;
    }
    
    /**
     * Retrieve the signing credentials of this OA Server. 
     * 
     * These credentials contain the server provate key and can be used for 
     * siging.
     * @param crypto The OA crypto manager.
     * @param sMyEntityID The entity ID of this OA Server.
     * @return The OA Server credentials.
     * @throws OAException If OA signing is disabled.
     */
    public static X509Credential retrieveMySigningCredentials(
        CryptoManager crypto, String sMyEntityID) throws OAException
    {
        PrivateKey key = crypto.getPrivateKey();
        if(key == null)
        {    
            _logger.warn(
                "No correct private key configured, signing is disabled");
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        BasicX509Credential signingCredential = new BasicX509Credential();        
        signingCredential.setEntityCertificate((X509Certificate)crypto.getCertificate());
        signingCredential.setEntityId(sMyEntityID);
        signingCredential.setPrivateKey(key);
        signingCredential.setUsageType(UsageType.SIGNING);
        return signingCredential;
    }
    
    /**
     * Retrieve the signing credentials of the given issuer.
     * The global Signing Keystore facility of the server is used for the lookup. 
     * 
     * These credentials do not contain the private key and can only 
     * be used for signature validation.
     * 
     * @param crypto The OA crypto manager.
     * @param sEntityID The issuer.
     * @return The signing credentials of the given issuer, or null if not found.
     * @throws CryptoException If OA signing is disabled or certificate could not 
     *  be retrieved.
     * @throws CryptoException if retrieval fails
     */
    public static X509Credential retrieveSigningCredentials(
        CryptoManager crypto, String sEntityID) throws CryptoException
    {        
        BasicX509Credential signingCredential = null;
        try
        {            
            X509Certificate certificate = (X509Certificate)crypto.getCertificate(
                sEntityID);
            if(certificate == null)
            {
                _logger.debug(
                    "No certificate found in OA Crypto Manager with alias: " + sEntityID);
                throw new CryptoException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            signingCredential = new BasicX509Credential();        
            signingCredential.setEntityCertificate(certificate);
            signingCredential.setEntityId(sEntityID);
            signingCredential.setUsageType(UsageType.SIGNING);    
            
        }
        catch(CryptoException e)
        {
            _logger.debug(
                "Could not retrieve signing credentials from crypto manager's signing facility");
            throw e;
        }
        return signingCredential;
    }
    
    /**
     * Returns the digest method algorith of the supplied message digest.
     * @param messageDigest The message digest.
     * 
     * @return SecurityConfiguration for generating signatures
     * @throws OAException if algorithm is not supported
     */
    public static String getXMLDigestMethodURI(MessageDigest messageDigest) 
        throws OAException
    {
        String sDigestAlgorithm = messageDigest.getAlgorithm();
        sDigestAlgorithm = sDigestAlgorithm.replace("-", "");
        
        if (sDigestAlgorithm.equalsIgnoreCase("SHA1"))
            return SignatureConstants.ALGO_ID_DIGEST_SHA1;
        else if (sDigestAlgorithm.equalsIgnoreCase("SHA256"))
            return EncryptionConstants.ALGO_ID_DIGEST_SHA256;
        else if (sDigestAlgorithm.equalsIgnoreCase("SHA384"))
            return SignatureConstants.ALGO_ID_DIGEST_SHA384;
        else if (sDigestAlgorithm.equalsIgnoreCase("SHA512"))
            return EncryptionConstants.ALGO_ID_DIGEST_SHA512;
        else if (sDigestAlgorithm.equalsIgnoreCase("MD5"))
            return SignatureConstants.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5;
        else
        {
            //DD Only a limited number of digest algorithms are supported in OA SAML2
            _logger.error("Unsupported message digest algorithm: " + sDigestAlgorithm);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    } 
}
