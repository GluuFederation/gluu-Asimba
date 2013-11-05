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
package com.alfaariss.oa.engine.core.crypto;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.crypto.factory.AbstractCipherFactory;
import com.alfaariss.oa.engine.core.crypto.factory.AbstractSigningFactory;

/**
 * A Manager for cryptographic functionality.
 *
 * DD Uses configured providers for cryptographic functionality.  
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 * @see <a href="http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#ProviderInstalling">ProviderInstalling</a>
 */
public class CryptoManager implements IComponent 
{   
    private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA1withRSA";
    private static final String DEFAULT_RANDOM_ALGORITHM = "SHA1PRNG";
    private static final String DEFAULT_ENCRYPTION_ALGORITHM = "DESede";
    private static final String DEFAULT_DIGEST_ALGORITHM = "SHA1";
    
    private static Log _logger;
    private IConfigurationManager _configManager;
    
	private SecretKey _secretKey;
	private String _sMessageDigestAlgorithm;
    private String _sMessageDigestProvider;
    private String _sCipherAlgorithm;
    private String _sCipherProvider;
    private SecureRandom _secureRandom;
    private AbstractCipherFactory _cipherFactory;
    private String _sSigningAlgorithm;
    private String _sSigningProvider;
    private PrivateKey _privateKey;
    private Certificate _certificate;
    private AbstractSigningFactory _signingFactory;
    
    /**
     * Create a new <code>CryptoManager</code>.
     */
    public CryptoManager()
    {
        //retrieve handle to configuration and logger
        _logger = LogFactory.getLog(CryptoManager.class); 
    }

    /**
     * Start the <code>CryptoManager</code>. 
     * 
     * <ul>
     *  <li>Read algorithms and providers from configuration if available</li>
     *  <li>Create Engine's (e.g. SecureRandom, )</li>
     *  <li>Create and read keys (factory->createSecretKey())</li>
     * </ul>
     * 
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager
        , Element eConfig) throws OAException
    {        
        _configManager = oConfigurationManager;
        //read encryption configuration
        readEncryptionConfig(eConfig);
        //read signature configuration
        readSigningConfig(eConfig);
        //read random configuration
        readRandomConfig(eConfig);
        //read message digest configuration
        readMessageDigestConfig(eConfig);       
    }

    /**
     * Restart the <code>CryptoManager</code>.
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element eConfig) throws CryptoException
    {   
        try
        {
            synchronized (this)
            {
                //read encryption configuration
                if(_cipherFactory != null)
                    _cipherFactory.stop();
                readEncryptionConfig(eConfig);
                //read signature configuration
                readSigningConfig(eConfig);
                //read random configuration
                readRandomConfig(eConfig); 
                //read message digest configuration
                readMessageDigestConfig(eConfig);
            }
        }
        catch (CryptoException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Internal error during restart", e);
            throw new CryptoException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
	 * Retrieve an instance of the configured {@link SecureRandom}.
	 * @return The configured type of secure random.
     * @see <a href="http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#SecureRandom">The SecureRandom Class</a>
	 */
	public SecureRandom getSecureRandom()
    {
        //SecureRandom is thread save
		return _secureRandom;
	}
    
    /**
     * Retrieve an instance of the configured {@link MessageDigest}.    
     * @return The configured type of message digest.
     * @throws CryptoException  If creation fails. 
     * @see <a href="http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#MessageDigest">The MessageDigest Class</a>
     */
    public MessageDigest getMessageDigest() throws CryptoException
    {   
        MessageDigest messageDigest = null;       
        try
        {
            if (_sMessageDigestProvider != null)
            {
                messageDigest = MessageDigest.getInstance(
                    _sMessageDigestAlgorithm, _sMessageDigestProvider);
            }
            else
            {
                messageDigest = MessageDigest.getInstance(_sMessageDigestAlgorithm);
            }           
        }
        catch (NoSuchAlgorithmException e)
        {
           
            _logger.error("Invalid message digest algorithm", e);
            throw new CryptoException(SystemErrors.ERROR_INTERNAL);
        }
        catch (NoSuchProviderException e)
        {
            _logger.error("Invalid message digest provider", e);
            throw new CryptoException(SystemErrors.ERROR_INTERNAL);
        }
        return messageDigest;
    }
    
    /**
     * Retrieve an instance of the configured {@link Cipher}.    
     * @return The configured type of Cipher.
     * @throws CryptoException If creation fails. 
     * @see <a href="http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#CipherClass">The Cipher Class</a>
     */
	public Cipher getCipher() throws CryptoException
    {        
        Cipher cipher = null;
        if(_sCipherAlgorithm != null) //Encryption enabled
        {
    		try
            {
                if (_sCipherProvider != null)
                    cipher = Cipher.getInstance(_sCipherAlgorithm, _sCipherProvider);
                else
                    cipher = Cipher.getInstance(_sCipherAlgorithm);            
            }
            catch (NoSuchAlgorithmException e)
            {
                _logger.error("Invalid cipher algorithm", e);
                throw new CryptoException(SystemErrors.ERROR_INTERNAL);
            }
            catch (NoSuchProviderException e)
            {
                _logger.error("Invalid cipher provider", e);
                throw new CryptoException(SystemErrors.ERROR_INTERNAL);
            }
            catch (NoSuchPaddingException e)
            {
                _logger.error("Padding exception", e);
                throw new CryptoException(SystemErrors.ERROR_INTERNAL);
            }
        }
        else
            _logger.debug("Encryption disabled"); 
        return cipher;
	}
   
     /**
     * Retrieve the OA server SecretKey.    
     * 
     * The secret key is retrieved using a {@link AbstractCipherFactory} 
     * instance. 
     * @return The SecretKey of this OA server.
     * @see CryptoManager#getCipher()
     */
	public SecretKey getSecretKey()
    {
		return _secretKey;
	}    
  
    /**
     * Retrieve an instance of the configured {@link Signature}.    
     * @return The configured type of Signature.
     * @throws CryptoException If creation fails. 
     * @see <a href="http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#Signature">
     *  The Signature Class</a>
     */
    public Signature getSignature() throws CryptoException
    {
        Signature signature = null;
        if(_sSigningAlgorithm != null) //Signing enabled
        {
            try
            {
                if (_sSigningProvider != null)
                    signature = Signature.getInstance(
                        _sSigningAlgorithm, _sSigningProvider);
                else
                    signature = Signature.getInstance(_sSigningAlgorithm);
            }
            catch (NoSuchAlgorithmException e)
            {
                _logger.error("Invalid signature algorithm", e);
                throw new CryptoException(SystemErrors.ERROR_INTERNAL);
            }
            catch (NoSuchProviderException e)
            {
                _logger.error("Invalid signature provider", e);
                throw new CryptoException(SystemErrors.ERROR_INTERNAL);
            }     
        }
        else
            _logger.debug("Signing disabled");
        
        _logger.debug("Established Signature instance of provider " + signature.getProvider().getName());
        return signature;
        
    }
    
    /**
     * Retrieve the server PrivateKey for signing purposes.    
     * 
     * The secret key is retrieved using an {@link AbstractSigningFactory} instance. 
     * @return The PrivateKey of this server.
     * @see CryptoManager#getSignature()
     */
    public PrivateKey getPrivateKey()
    {
        return _privateKey;        
    }
    
    /**
     * Retrieve the OAS certificate for signing purposes. 
     *
     * The certificate is retrieved using an {@link AbstractSigningFactory} instance.
     * @return The certificate of this server.
     */
    public Certificate getCertificate()
    {
        return _certificate;        
    }
    
    /**
     * Retrieve an trusted certificate. 
     *
     * The certificate is retrieved using an {@link AbstractSigningFactory} instance.
     * @param sAlias The alias of the certificate.
     * @return The certificate of this server.
     * @throws CryptoException If retrieving of the certificate fails.
     */
    public Certificate getCertificate(String sAlias) throws CryptoException
    {
        if(_signingFactory == null)
        {
            _logger.debug("Signing disabled");
            return null;
        }       
        return _signingFactory.getCertificate(sAlias);
    }
    
    /**
     * Retrieve the signing factory.
     * @return The signing factory.
     * @since 1.4
     */
    public AbstractSigningFactory getSigningFactory()
    {
        return _signingFactory;
    }

	/**
	 * Stop the <code>CryptoManager</code>.
	 * @see com.alfaariss.oa.api.IComponent#stop()
	 */
	public void stop()
    {
        if(_cipherFactory != null)
            _cipherFactory.stop();
	}
    
    //Read the crypto
    private void readEncryptionConfig(
        Element eCryptoSection) throws CryptoException 
    {
        Element eCipherSection = null;
        Element eCipherFactorySection = null;       
        
        try
        {        
            eCipherSection = _configManager.getSection(
                eCryptoSection, "encryption");          
            if(eCipherSection == null)
            {
                _logger.info("Could not retrieve 'encryption' config section, encryption disabled");
            }
            else
            {
            
                //retrieve algorithm
                try
                {                
                    _sCipherAlgorithm = _configManager.getParam(
                        eCipherSection, "algorithm");
                    if(_sCipherAlgorithm == null)
                    {
                        _sCipherAlgorithm = DEFAULT_ENCRYPTION_ALGORITHM;            
                        _logger.info("Could not retrieve 'algorithm' config parameter. Using default algorithm");
                    }
                }
                catch (ConfigurationException e)
                {
                    _logger.error("Could not read 'algorithm' config parameter", e);
                    throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
                }
                      
                // retrieve provider
                try
                {
                    _sCipherProvider = _configManager.getParam(
                        eCipherSection, "provider");
                    if(_sCipherProvider == null)
                    {        
                        _logger.info("Could not retrieve 'provider' config parameter. Using default first suitable provider.");
                    }
                }
                catch (ConfigurationException e)
                {
                    _logger.error("Could not read 'provider' config parameter", e);
                    throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
                }            
                
                //Create factory for key generation
                eCipherFactorySection = _configManager.getSection(
                    eCipherSection, "cipherfactory");          
                if(eCipherFactorySection == null)
                {                          
                    _logger.error(
                        "Could not retrieve valid 'cipherfactory' config section");
                    throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                //Instantiate factory and retrieve key
                _cipherFactory = AbstractCipherFactory.createInstance(
                    _configManager, eCipherFactorySection);                        
                _cipherFactory.start();
                _secretKey = _cipherFactory.getSecretKey(
                    _sCipherAlgorithm, _sCipherProvider);
                        
                //Test provider and algorithm 
                getCipher();
            }
        }
        catch(CryptoException e)
        {
            throw e;
        }        
        catch(Exception e)
        {
            _logger.fatal("Internal error during crypto init", e);
            throw new CryptoException(SystemErrors.ERROR_INTERNAL); 
        }       
    }
    
    //Read the message digest
    private void readMessageDigestConfig(
        Element eCryptoSection) throws CryptoException 
    {
        Element eDigestSection = null;
        
        try
        {        
            eDigestSection = _configManager.getSection(
                eCryptoSection, "message_digest");             
            if(eDigestSection == null)
            {
                _sMessageDigestAlgorithm = DEFAULT_DIGEST_ALGORITHM;            
                _logger.info(
                    "Could not retrieve 'message_digest' config section. Using default algorithm and provider");
            }
            else //Encryption configured
            {
            
            
                //retrieve algorithm
                try
                {                
                    _sMessageDigestAlgorithm = _configManager.getParam(
                        eDigestSection, "algorithm");
                    if(_sMessageDigestAlgorithm == null)
                    {
                        _sMessageDigestAlgorithm = DEFAULT_DIGEST_ALGORITHM;            
                        _logger.info(
                            "Could not retrieve 'algorithm' config parameter. Using default algorithm");
                    }
                }
                catch (ConfigurationException e)
                {
                    _logger.error("Could not read 'algorithm' config parameter", e);
                    throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
                }
                      
                // retrieve provider
                try
                {
                    _sMessageDigestProvider = _configManager.getParam(
                        eDigestSection, "provider");
                    if(_sMessageDigestProvider == null)
                    {        
                        _logger.info(
                            "Could not retrieve 'provider' config parameter. Using first suitable provider");
                    }
                }
                catch (ConfigurationException e)
                {
                    _logger.error("Could not read 'provider' config parameter", e);
                    throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                //Test provider and algorithm
                getMessageDigest();                
            }
        }
        catch(CryptoException e)
        {
            throw e;
        }    
        catch(Exception e)
        {
            _logger.fatal("Internal error during crypto init", e);
            throw new CryptoException(SystemErrors.ERROR_INTERNAL); 
        }       
    }
    
    //Read the signature configuration and initialize
    private void readSigningConfig(
        Element eCryptoSection) throws CryptoException 
    {
        Element eSigningSection = null;
        Element eSigningFactorySection = null;       
        
        try
        {        
            eSigningSection = _configManager.getSection(
                eCryptoSection, "signing");          
            if(eSigningSection == null)
            {
                _signingFactory = null;
                _privateKey = null;
                _certificate = null;
                _sSigningProvider = null;
                _sSigningAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;
                _logger.info(
                    "Could not retrieve 'signing' config section, signing disabled");
            }
            else
            {
            
                //retrieve algorithm
                try
                {                
                    _sSigningAlgorithm = _configManager.getParam(
                        eSigningSection, "algorithm");
                    if(_sSigningAlgorithm == null)
                    {
                        _sSigningAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;            
                        _logger.info(
                            "Could not retrieve 'algorithm' config parameter. Using default algorithm");
                    }
                }
                catch (ConfigurationException e)
                {
                    _logger.error("Could not read 'algorithm' config parameter", e);
                    throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
                }
                      
                // retrieve provider
                try
                {
                    _sSigningProvider = _configManager.getParam(
                        eSigningSection, "provider");
                    if(_sSigningProvider == null)
                    {        
                        _logger.info(
                            "Could not retrieve 'provider' config parameter. Using first suitable provider");
                    }
                }
                catch (ConfigurationException e)
                {
                    _logger.error("Could not read 'provider' config parameter", e);
                    throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
                }            
                
                //Create factory for key generation
                eSigningFactorySection = _configManager.getSection(
                    eSigningSection, "signingfactory");          
                if(eSigningFactorySection == null)
                {                          
                    _logger.error(
                        "Could not retrieve valid 'signingfactory' config section");
                    throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
                }                
                //Instantiate factory and retrieve key + certificate
                _signingFactory = AbstractSigningFactory.createInstance(
                    _configManager, eSigningFactorySection);
                _signingFactory.start();
                _privateKey = _signingFactory.getPrivateKey();
                _certificate = _signingFactory.getCertificate();               
                
                //Test provider and algorithm
                getSignature();
            }
        }
        catch(CryptoException e)
        {
            throw e;
        }        
        catch(Exception e)
        {
            _logger.fatal("Internal error during signing init", e);
            throw new CryptoException(SystemErrors.ERROR_INTERNAL); 
        }       
       
    }
    
    //  Read the random configuration and initialize
    private void readRandomConfig(Element eCryptoSection) throws CryptoException 
    {
        //<random_generator algorithm="SHA1PRNG" provider="CryptixCrypto"/>
        Element eRandomSection = null;
        String sRandomAlgorithm = null;
        String sRandomProvider = null;
        
        try
        {        
            eRandomSection = _configManager.getSection(
                eCryptoSection, "random_generator");          
            if(eRandomSection == null)
            {
                sRandomAlgorithm = DEFAULT_RANDOM_ALGORITHM;            
                _logger.info(
                    "Could not retrieve 'random' config section. Using default algorithm and provider");
            }
            else //Encryption configured
            {
                //retrieve algorithm
                try
                {                
                    sRandomAlgorithm = _configManager.getParam(
                        eRandomSection, "algorithm");
                    if(sRandomAlgorithm == null)
                    {
                        sRandomAlgorithm = DEFAULT_RANDOM_ALGORITHM;            
                        _logger.info(
                            "Could not retrieve 'algorithm' config parameter. Using default algorithm");
                    }
                }
                catch (ConfigurationException e)
                {
                    _logger.error("Could not read 'algorithm' config parameter"
                        , e);
                    throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
                }
                      
                // retrieve provider
                try
                {
                    sRandomProvider = _configManager.getParam(eRandomSection, 
                        "provider");
                    if(sRandomProvider == null)
                    {        
                        _logger.info(
                            "Could not retrieve 'provider' config parameter. Using first suitable provider");
                    }
                }
                catch (ConfigurationException e)
                {
                    _logger.error("Could not read 'provider' config parameter"
                        , e);
                    throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
                }
            }            
            
            //Secure Random
            if(sRandomProvider == null)
                _secureRandom = SecureRandom.getInstance(sRandomAlgorithm);
            else
                _secureRandom = SecureRandom.getInstance(sRandomAlgorithm, 
                       sRandomProvider);
            
        }
        catch(CryptoException e)
        {
            throw e;
        }      
        catch (NoSuchAlgorithmException e)
        {
            _logger.error("Invalid random algorithm", e);
            throw new CryptoException(SystemErrors.ERROR_INIT);
        }
        catch (NoSuchProviderException e)
        {
            _logger.error("Invalid random provider", e);
            throw new CryptoException(SystemErrors.ERROR_INIT);
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during configuration reading", e);
            throw new CryptoException(SystemErrors.ERROR_INTERNAL); 
        }    
    }
    
    
}