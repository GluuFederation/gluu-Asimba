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
/* 
 * Changes
 * 
 * - support for relative paths based on mounting-points (2012/03)
 * 
 * Copyright Asimba - www.asimba.org
 * 
 */

package com.alfaariss.oa.engine.crypto.keystore;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.utility.filesystem.PathTranslator;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.engine.core.crypto.CryptoException;
import com.alfaariss.oa.engine.core.crypto.factory.AbstractSigningFactory;

/**
 * A factory which reads the signing keys from a keystore.
 * 
 * @author EVB
 * @author Alfa & Ariss
 * @author mdobrinic@asimba
 * 
 * @see KeyStore
 */
public class KeystoreSigningFactory extends AbstractSigningFactory
{
    private final static String DEFAULT_ALIAS = "mykey";

    private Log _logger;
    private KeyStore _keystore;
    private KeyStore _certificatestore;
    private String _sKeystorePassword;
    private String _sPassword;
    private String _sAlias;

    /**
     * Create a new <code>KeystoreSigningFactory</code> instance.
     */
    public KeystoreSigningFactory ()
    {
        _logger = LogFactory.getLog(KeystoreSigningFactory.class);
    }

    /**
     * Initialize the <code>KeystoreSigningFactory</code>.
     * 
     * Read configuration:
     * <dl>
     * <dt>key store</dt>
     * <dd>
     * <ul>
     * <li>file</li>
     * <li>type</li>
     * <li>password</li>
     * </ul>
     * </dd>
     * <dt>certificate store</dt>
     * <dd>
     * <ul>
     * <li>file</li>
     * <li>type</li>
     * <li>password</li>
     * </ul>
     * </dd>
     * <dt>alias</dt>
     * <dd>The key alias</dd>
     * <dt>password</dt>
     * <dd>The private key password</dd>
     * </dl>
     * 
     * The configuration and key store is validated upon initialization.
     * 
     * @see AbstractSigningFactory#start()
     */
    public void start() throws CryptoException
    {
        try
        {
            Element eKeystore = _configurationManager.getSection(_eSection,
                "keystore");

            Element eTruststore = _configurationManager.getSection(_eSection,
                "truststore");

            if (eKeystore == null && eTruststore == null)
            {
                _logger
                    .error("Could not retrieve 'keystore' or 'truststore' section in config");
                throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
            }

            if (eKeystore != null)
            {
                _keystore = loadKeystore(eKeystore);

                // Read alias
                _sAlias = _configurationManager.getParam(eKeystore, "alias");
                if (_sAlias == null)
                {
                    _sAlias = DEFAULT_ALIAS;
                    _logger
                        .info("Could not retrieve 'alias' paramater, using default: "
                            + DEFAULT_ALIAS);
                }

                // Read password
                _sPassword = _configurationManager.getParam(eKeystore,
                    "password");
                if (_sPassword == null)
                {
                    _logger.error("No 'password' parameter supplied");
                    throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
                }

                // Test alias
                if (!_keystore.containsAlias(_sAlias))
                {
                    _logger
                        .error("Configured alias does not exist: " + _sAlias);
                    throw new CryptoException(SystemErrors.ERROR_INIT);
                }
                // Test key
                if (!_keystore.isKeyEntry(_sAlias))
                {
                    _logger.error("Configured alias is not a valid key entry: "
                        + _sAlias);
                    throw new CryptoException(SystemErrors.ERROR_INIT);
                }

                _logger.info("Succesfully loaded: keystore");
            }
            else
            {
                _keystore = null;
                _logger.info("Disabled: keystore");
            }

            if (eTruststore != null)
            {
                _certificatestore = loadKeystore(eTruststore);
                _logger.info("Succesfully loaded: truststore");
            }
            else
            {
                _certificatestore = null;
                _logger.info("Disabled: truststore");
            }
        }
        catch (KeyStoreException e)
        {
            _logger.error("Could not load keystore", e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }
        catch (ConfigurationException e)
        {
            _logger.error("Could not initialize signing, configuration error",
                e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }
    }

    /**
     * Retrieve the trusted certificate from the key store.
     * 
     * @see AbstractSigningFactory#getCertificate(java.lang.String)
     */
    public Certificate getCertificate(String sAlias) throws CryptoException
    {
        Certificate certificate = null;
        try
        {
            if (_certificatestore == null)
                return null;

            certificate = _certificatestore.getCertificate(sAlias);
            if (!(certificate instanceof java.security.cert.X509Certificate))
            {
                _logger.error("Could not find a valid certificate with alias "
                    + sAlias);
                throw new CryptoException(SystemErrors.ERROR_CRYPTO_CREATE);
            }
        }
        catch (CryptoException e)
        {
            throw e;
        }
        catch (KeyStoreException e)
        {
            _logger.error("Could not load keystore", e);
            throw new CryptoException(SystemErrors.ERROR_INTERNAL, e);
        }
        return certificate;
    }

    /**
     * Retrieve the private key certificate from the key store.
     * 
     * @see AbstractSigningFactory#getCertificate()
     */
    public Certificate getCertificate() throws CryptoException
    {
        Certificate certificate = null;
        try
        {
            if (_keystore == null)
                return null;

            certificate = _keystore.getCertificate(_sAlias);
            if (!(certificate instanceof java.security.cert.X509Certificate))
            {
                _logger.error("Could not find a valid certificate with alias "
                    + _sAlias);
                throw new CryptoException(SystemErrors.ERROR_CRYPTO_CREATE);
            }
        }
        catch (CryptoException e)
        {
            throw e;
        }
        catch (KeyStoreException e)
        {
            _logger.error("Could not load keystore", e);
            throw new CryptoException(SystemErrors.ERROR_INTERNAL, e);
        }
        return certificate;
    }

    /**
     * Retrieve the private key from the key store.
     * 
     * @see AbstractSigningFactory#getPrivateKey()
     */
    public PrivateKey getPrivateKey() throws CryptoException
    {
        Key key = null;
        try
        {
            if (_keystore == null)
                return null;

            key = _keystore.getKey(_sAlias, _sPassword.toCharArray());
            if (!(key instanceof PrivateKey))
            {
                _logger.error("Could not find a valid private key with alias "
                    + _sAlias);
                throw new CryptoException(SystemErrors.ERROR_CRYPTO_CREATE);
            }
        }
        catch (CryptoException e)
        {
            throw e;
        }
        catch (KeyStoreException e)
        {
            _logger.error("Could not load keystore", e);
            throw new CryptoException(SystemErrors.ERROR_RESOURCE_CONNECT, e);
        }
        catch (NoSuchAlgorithmException e)
        {
            _logger.error("Could not load keystore, no such algorithm", e);
            throw new CryptoException(SystemErrors.ERROR_INTERNAL, e);
        }
        catch (UnrecoverableKeyException e)
        {
            _logger.error("Could not load keystore,unrecoverable key error", e);
            throw new CryptoException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
        }
        return (PrivateKey)key;
    }

    /**
     * @see AbstractSigningFactory#getAlias()
     */
    @Override
    public String getAlias()
    {
        return _sAlias;
    }

    /**
     * @see AbstractSigningFactory#getPrivateKeyPassword()
     */
    @Override
    public String getPrivateKeyPassword() throws CryptoException
    {
        return _sPassword;
    }

    /**
     * @see AbstractSigningFactory#getKeyStore()
     */
    public KeyStore getKeyStore()
    {
        return _keystore;
    }
    
    /** 
     * Retrieve aliases from trust store.
     * @see AbstractSigningFactory#getAliases()
     */
    public Enumeration<String> getAliases() throws CryptoException
    {
        try
        {
            return _certificatestore.aliases();
        }
        catch (KeyStoreException e)
        {
            _logger.warn("Could not retrieve certificate aliases", e);
            throw new CryptoException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
    }
    
    /**
     * Retrieve alias from trust store.
     * @see AbstractSigningFactory#getCertificateAlias(
     *  java.security.cert.Certificate)
     */
    public String getCertificateAlias(Certificate cert) throws CryptoException
    {
        try
        {
            return _certificatestore.getCertificateAlias(cert);
        }
        catch (KeyStoreException e)
        {
            _logger.warn("Could not retrieve alias for certificate: " + cert, e);
            throw new CryptoException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
    }

    /**
     * Retrieve alias from the certificate store.
     * @see AbstractSigningFactory#getAliasForX509Cert(
     *  java.lang.String, java.math.BigInteger)
     */
    public String getAliasForX509Cert(String issuer, BigInteger serialNumber)
        throws CryptoException
    {
        X500Principal issuerRDN = new X500Principal(issuer);
        Certificate cert = null;

        try
        {
            Enumeration<String> aliases = _certificatestore.aliases();
            while (aliases.hasMoreElements())
            {
                String alias = aliases.nextElement();
                Certificate[] certs = _certificatestore
                    .getCertificateChain(alias);
                if (certs == null || certs.length == 0)
                {
                    // no cert chain
                    cert = _certificatestore.getCertificate(alias);
                    if (cert == null)
                    {
                        return null;
                    }
                }
                else
                {
                    cert = certs[0];
                }

                if (cert instanceof X509Certificate)
                {
                    X509Certificate x509cert = (X509Certificate)cert;
                    if (serialNumber == null
                        || x509cert.getSerialNumber().compareTo(serialNumber) == 0)
                    {
                        X500Principal certRDN = new X500Principal(x509cert
                            .getIssuerDN().getName());
                        if (certRDN.equals(issuerRDN))
                        {
                            return alias;
                        }
                    }
                }
            }
        }
        catch (KeyStoreException e)
        {
            _logger.error("Could not read alias from trust store", e);
            throw new CryptoException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
        }
        return null;
    }

    private KeyStore loadKeystore(Element eKeystore) throws CryptoException
    {
        KeyStore keystore = null;
        try
        {
            String sKeystoreType = _configurationManager.getParam(eKeystore,
                "type");
            if (sKeystoreType == null)
            {
                sKeystoreType = KeyStore.getDefaultType();
                _logger
                    .info("Could not retrieve keystore 'type' paramater, using default: "
                        + sKeystoreType);
            }

            String sKeystoreFile = _configurationManager.getParam(eKeystore,
                "file");
            if (sKeystoreFile == null)
            {
                _logger.error("Could not retrieve keystore 'file' parameter");
                throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            // Establish real filename:
            sKeystoreFile = PathTranslator.getInstance().map(sKeystoreFile).trim();

            char[] caKeystorePassword = null;
            _sKeystorePassword = _configurationManager.getParam(eKeystore,
                "keystore_password");
            if (_sKeystorePassword == null)
            {
                _logger
                    .info("No optional 'keystore_password' parameter supplied");
            }
            else
            {
                caKeystorePassword = _sKeystorePassword.toCharArray();
            }

            keystore = KeyStore.getInstance(sKeystoreType);
            keystore.load(new FileInputStream(sKeystoreFile),
                caKeystorePassword);

            _logger.info("Loaded keystore: " + sKeystoreFile);
        }
        catch (KeyStoreException e)
        {
            _logger.error("Could not load keystore", e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }
        catch (NoSuchAlgorithmException e)
        {
            _logger.error("Could not load keystore, no such algorithm", e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }
        catch (CertificateException e)
        {
            _logger.error("Could not load keystore, certificate error", e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }
        catch (FileNotFoundException e)
        {
            _logger.error("Could not load keystore, file not found", e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }
        catch (IOException e)
        {
            _logger.error("Could not load keystore, I/O error", e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }
        catch (ConfigurationException e)
        {
            _logger.error("Could not read keystore configuration", e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }

        return keystore;
    }
}