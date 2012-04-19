/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2008 Alfa & Ariss B.V.
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
package com.alfaariss.oa.profile.aselect.ws.security;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoException;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.crypto.factory.AbstractSigningFactory;


/**
 * OAS specific {@link Crypto} implementation which uses the 
 *  {@link CryptoManager}. 
 * 
 * <br><br><i>Partitially based on sources from the Apache Web Services project
 * (http://ws.apache.org/)</i>
 * 
 * @author EVB
 * @author Alfa & Ariss
 * @since 1.4
 */
public class OACrypto implements Crypto
{
    private AbstractSigningFactory _factory;
    private static CertificateFactory _certFactory;
    private static Log _logger;
    
    /**
     * Create new {@link OACrypto} using the engine.
     * 
     * Requires an initialized {@link Engine} with signing enabled.
     * 
     * @throws OAException If retrieval of signing factory fails.
     */
    public OACrypto() throws OAException
    {
        _logger = LogFactory.getLog(OACrypto.class);
        try
        {
            CryptoManager manager = Engine.getInstance().getCryptoManager();
            if(manager == null)
            {
                _logger.warn(
                    "Could not create OACrypto, OAS cryptomanager not initialized");
                throw new OAException(SystemErrors.ERROR_CRYPTO_CREATE);
            }
            
            _factory = manager.getSigningFactory();
            if(_factory == null)
            {
                _logger.warn(
                    "Could not create OACrypto, OAS signing not enabled");
                throw new OAException(SystemErrors.ERROR_CRYPTO_CREATE);
            }            
        }
        catch(OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.error(
                "Could not create OACrypto, due to internal error", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Used by WSS4J to initialize.
     * @param properties The crypto proprties (not used)
     * @throws OAException If ceration fails.
     */
    public OACrypto(Properties properties) throws OAException
    {
        this();
    }

    /**
     * Used by WSS4J to initialize.
     * @param properties The crypto proprties (not used)
     * @param loader The classloader to be used.
     * @throws OAException If ceration fails.
     */
    public OACrypto(
        Properties properties, ClassLoader loader) throws OAException
    {
        this();
    }
    
    /**
     * Create new {@link OACrypto} using the given factory.
     * @param factory The signing factory to be used.
     */
    public OACrypto(AbstractSigningFactory factory)   
    {
        _logger = LogFactory.getLog(OACrypto.class);
        _factory = factory;
    }
    
    /**
     * @see Crypto#getAliasForX509Cert(java.security.cert.Certificate)
     */
    public String getAliasForX509Cert(Certificate cert)
        throws WSSecurityException
    {
        try
        {
            String alias = _factory.getCertificateAlias(cert);
            if (alias == null)
            {
                // Search
                Enumeration<String> aliases = _factory.getAliases();
                while (alias == null & aliases.hasMoreElements())
                {
                    String tAlias = aliases.nextElement();
                    X509Certificate tempCert = 
                        (X509Certificate)_factory.getCertificate(alias);
                    if (tempCert.equals(cert))
                    {
                        alias = tAlias;
                    }
                }
            }                      
            return alias;
        }
        catch(CryptoException e)
        {
            _logger.error("Could not retrieve alias for X509 certificate", e);
            throw new WSSecurityException(WSSecurityException.FAILURE);
        }
    }

    /**
     * @see Crypto#getAliasForX509Cert(java.lang.String)
     */
    public String getAliasForX509Cert(String issuer) throws WSSecurityException
    {
        try
        {
            return _factory.getAliasForX509Cert(issuer, null);
        }
        catch (OAException e)
        {
            _logger.error("Could not retrieve alias for issuer", e);
            throw new WSSecurityException(WSSecurityException.FAILURE);
        }
    }
    
    /**
     * @see org.apache.ws.security.components.crypto.Crypto#getAliasForX509Cert(
     *  java.lang.String, java.math.BigInteger)
     */
    public String getAliasForX509Cert(String issuer, BigInteger serialNumber)
    throws WSSecurityException
    {
        try
        {
            return _factory.getAliasForX509Cert(issuer, serialNumber);
        }
        catch (OAException e)
        {
            _logger.error(
                "Could not retrieve alias for issuer and serial number", e);
            throw new WSSecurityException(WSSecurityException.FAILURE);
        }
    }

    /**
     * Not supported by OAS.
     * @see org.apache.ws.security.components.crypto.Crypto#getAliasForX509Cert(byte[])
     */
    public String getAliasForX509Cert(byte[] skiBytes) throws WSSecurityException
    {
        //TODO EVB: implement getAliasForX509Cert
        _logger.error(
            "Could not retrieve alias for SubjectKeyIdentifier, not supported");
        throw new WSSecurityException(WSSecurityException.FAILURE);
    }  

    /**
     * Not supported by OAS.
     * @see org.apache.ws.security.components.crypto.Crypto#getAliasForX509CertThumb(byte[])
     */
    public String getAliasForX509CertThumb(byte[] arg0)
        throws WSSecurityException
    {
        //TODO EVB: implement getAliasForX509CertThumb
        _logger.error(
            "Could not retrieve alias for Thumbprint, not supported");
        throw new WSSecurityException(WSSecurityException.FAILURE);
    }

    /**
     * Not supported by OAS.
     * @see org.apache.ws.security.components.crypto.Crypto#getAliasesForDN(java.lang.String)
     */
    public String[] getAliasesForDN(String arg0) throws WSSecurityException
    {
        //TODO EVB: implement getAliasesForDN
        _logger.error(
            "Could not retrieve alias for Thumbprint, not supported");
        throw new WSSecurityException(WSSecurityException.FAILURE);
    }

    /**
     * Retrieve 
     * @see Crypto#getCertificateData(boolean, X509Certificate[])
     */
    public byte[] getCertificateData(boolean reverse, X509Certificate[] certs)
        throws WSSecurityException
    {
       
        try 
        {
            Vector<X509Certificate> list = new Vector<X509Certificate>();
            for (int i = 0; i < certs.length; i++) 
            {
                if (reverse) 
                {
                    list.insertElementAt(certs[i], 0);
                } 
                else 
                {
                    list.add(certs[i]);
                }
            }
            CertPath path = getCertificateFactory().generateCertPath(list);
            return path.getEncoded();
        } 
        catch (CertificateEncodingException e) 
        {
            _logger.warn("Could not encode certificate path", e);
            throw new WSSecurityException(
                WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, "encodeError",
                null, e
            );
        } 
        catch (CertificateException e) 
        {
            _logger.warn("Could not generate certificate path", e);
            throw new WSSecurityException(
                WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, "parseError",
                null, e
            );
        }
    }

    /**
     * Retrieve the singleton instance of the certificate factory. 
     * @see org.apache.ws.security.components.crypto.Crypto#getCertificateFactory()
     */
    public CertificateFactory getCertificateFactory()
        throws WSSecurityException
    {
        if (_certFactory == null) 
        {
            try 
            {
                Provider provider = _factory.getKeyStore().getProvider();
                String sProvider = null;
                if(provider != null)
                {
                    sProvider = provider.getName();
                }
                if (sProvider == null || sProvider.length() == 0) 
                {
                    _certFactory = CertificateFactory.getInstance("X.509");
                } 
                else 
                {
                    _certFactory = CertificateFactory.getInstance(
                        "X.509", provider);
                }
            } 
            catch (CertificateException e) 
            {
                throw new WSSecurityException(
                    WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, 
                    "unsupportedCertType", null, e);
            }             
        }
        return _certFactory;
    }

    /**
     * Retrieve certificate from keystore or trustore.
     * @see org.apache.ws.security.components.crypto.Crypto#getCertificates(java.lang.String)
     */
    public X509Certificate[] getCertificates(String alias)
        throws WSSecurityException
    {
        try
        {
            //Check if own certificate is requested
            if(alias.equals(getDefaultX509Alias()))
            {
                return new X509Certificate[]{(
                    X509Certificate)_factory.getCertificate()};
            }
            return new X509Certificate[] { 
                   (X509Certificate)_factory.getCertificate(alias)};
        }
        catch (OAException e)
        {
            _logger.warn("Could not retrieve certificate", e);
            throw new WSSecurityException(
                WSSecurityException.FAILURE);
        }
    }

    /**
     * Retrieve the default alias.
     * @see org.apache.ws.security.components.crypto.Crypto#getDefaultX509Alias()
     */
    public String getDefaultX509Alias()
    {
        return _factory.getAlias();       
    }

    /**
     * @see org.apache.ws.security.components.crypto.Crypto#getKeyStore()
     */
    public KeyStore getKeyStore()
    {
        return _factory.getKeyStore();
    }

    /**
     * @see Crypto#getPrivateKey(java.lang.String, java.lang.String)
     */
    public PrivateKey getPrivateKey(String alias, String password) throws Exception
    {
        if(!alias.equals(getDefaultX509Alias()))
        {
            _logger.warn("Could not retrieve private key, alias invalid");
            throw new WSSecurityException(
                WSSecurityException.FAILURE);
        }
        if(!password.equals(_factory.getPrivateKeyPassword()))
        {
            _logger.warn("Could not retrieve private key, password invalid");
            throw new WSSecurityException(
                WSSecurityException.FAILURE);
        }
        return _factory.getPrivateKey();
    }

    /**
     * Not supported by OAS.
     * @see Crypto#getSKIBytesFromCert(java.security.cert.X509Certificate)
     */
    public byte[] getSKIBytesFromCert(X509Certificate arg0)
        throws WSSecurityException
    {
        //TODO EVB: implement getSKIBytesFromCert
        _logger.error(
            "Could not retrieve SKIBytes certificate, not supported");
        throw new WSSecurityException(WSSecurityException.FAILURE);
    }

    /**
     * Construct an array of certificate's.
     * @see Crypto#getX509Certificates(byte[], boolean)
     */
    public X509Certificate[] getX509Certificates(byte[] data, boolean reverse)
        throws WSSecurityException
    {
        X509Certificate[] certs = null;       
        try 
        {
            InputStream in = new ByteArrayInputStream(data);
            CertPath path = getCertificateFactory().generateCertPath(in);
            List<? extends Certificate> certificates = path.getCertificates();
            certs = new X509Certificate[certificates.size()];
            
            int i = 0, size = certificates.size();
            for(X509Certificate cert : certs)
                certs[(reverse) ? (size - 1 - i) : i] = cert;      
        } 
        catch (CertificateException e) 
        {
            throw new WSSecurityException(
                WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, 
                "parseError", null, e);
        }       
        return certs;
    }

    /**
     * Load a X509Certificate from the input stream.
     * @see Crypto#loadCertificate(java.io.InputStream)
     */
    public X509Certificate loadCertificate(InputStream in)
        throws WSSecurityException
    {
        X509Certificate cert = null;
        try 
        {
            cert = (X509Certificate) getCertificateFactory().generateCertificate(in);
        } 
        catch (CertificateException e) 
        {
            throw new WSSecurityException(
                WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, 
                "parseError", null, e);
        }
        return cert;
    }

    /**
     * Validate a given certificate chain.
     * @see Crypto#validateCertPath(java.security.cert.X509Certificate[])
     */
    public boolean validateCertPath(X509Certificate[] certs)
        throws WSSecurityException
    {
        boolean ok = false;
        try
        {
            // Generate cert path
            List<X509Certificate> certList = Arrays.asList(certs);
            CertPath path = this.getCertificateFactory().generateCertPath(
                certList);

            HashSet<TrustAnchor> set = new HashSet<TrustAnchor>();

            if (certs.length == 1) // Use factory certs
            {
                String alias = _factory.getAliasForX509Cert(certs[0]
                    .getIssuerDN().getName(), certs[0].getSerialNumber());
                if (alias == null)
                {
                    _logger.debug("Certificate not trusted");
                    return false;
                }

                X509Certificate cert = (X509Certificate)_factory
                    .getCertificate(alias);
                TrustAnchor anchor = new TrustAnchor(cert, cert
                    .getExtensionValue("2.5.29.30"));
                set.add(anchor);
            }
            else
            {
                // Add certificates from the keystore
                Enumeration aliases = _factory.getAliases();
                while (aliases.hasMoreElements())
                {
                    String alias = (String)aliases.nextElement();
                    X509Certificate cert = (X509Certificate)_factory
                        .getCertificate(alias);
                    TrustAnchor anchor = new TrustAnchor(cert, cert
                        .getExtensionValue("2.5.29.30"));
                    set.add(anchor);
                }
            }

            PKIXParameters param = new PKIXParameters(set);
            param.setRevocationEnabled(false);
            Provider provider = _factory.getKeyStore().getProvider();
            String sProvider = null;
            CertPathValidator certPathValidator = null;
            if (provider != null)
            {
                sProvider = provider.getName();
            }
            if (sProvider == null || sProvider.length() == 0)
            {
                certPathValidator = CertPathValidator.getInstance("PKIX");
            }
            else
            {
                certPathValidator = CertPathValidator.getInstance("PKIX",
                    sProvider);
            }
            certPathValidator.validate(path, param);
            ok = true;
        }
        catch (NoSuchProviderException e)
        {
            _logger.warn("No such provider", e);
            throw new WSSecurityException(WSSecurityException.FAILURE,
                "certpath", new Object[] {e.getMessage()}, e);
        }
        catch (NoSuchAlgorithmException e)
        {
            _logger.warn("No such algorithm", e);
            throw new WSSecurityException(WSSecurityException.FAILURE,
                "certpath", new Object[] {e.getMessage()}, e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            _logger.warn("Invalid algorithm param", e);
            throw new WSSecurityException(WSSecurityException.FAILURE,
                "certpath", new Object[] {e.getMessage()}, e);
        }
        catch (CertificateException e)
        {
            _logger.warn("Invalid certificate", e);
            throw new WSSecurityException(WSSecurityException.FAILURE,
                "certpath", new Object[] {e.getMessage()}, e);
        }
        catch (ClassCastException e)
        {
            _logger.warn("Certificate is not an X509Certificate", e);
            throw new WSSecurityException(WSSecurityException.FAILURE,
                "certpath", new Object[] {e.getMessage()}, e);
        }
        catch (CertPathValidatorException e)
        {
            _logger.warn("Could not validate Cert Path", e);
            throw new WSSecurityException(WSSecurityException.FAILURE,
                "certpath", new Object[] {e.getMessage()}, e);
        }
        catch (CryptoException e)
        {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                "certpath", new Object[] {e.getMessage()}, e);
        }
        return ok;
    }
}