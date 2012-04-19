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
package com.alfaariss.oa.engine.core.crypto.factory;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.crypto.CryptoException;

/**
 * A factory for generating and restoring cipher keys.
 * 
 * Implementations of this interface can be used to generate or read the private 
 * key and certificate of the OA server. These factories should be implemented 
 * using the abstract factory design pattern. 
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public abstract class AbstractSigningFactory 
{
    /** system logger */
    private static Log _logger = LogFactory.getLog(
        AbstractSigningFactory.class);    
    /** configuration manager */
    protected IConfigurationManager _configurationManager;
    /** configuration section */
    protected Element _eSection;
    
    /**
     * Create and initialize this factory.
     * @param configManager The configuration manager.
     * @param eConfig The configuration element of the factory.
     * @return The created instance.
     * @throws CryptoException If initializing fails
     */
    public static AbstractSigningFactory createInstance(
        IConfigurationManager configManager, Element eConfig) throws CryptoException
    {
        if(configManager == null)
            throw new IllegalArgumentException(
                "Supplied configuration manager is empty");
        if(eConfig == null)
            throw new IllegalArgumentException("Supplied section is empty");
        
        //retrieve factory
        String sSigningFactory = null;
        try
        {
            sSigningFactory = configManager.getParam(
                eConfig, "class");
            if(sSigningFactory == null)
            {        
                _logger.error("Could not retrieve 'class' config parameter");
                throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
            }                        
        }
        catch (ConfigurationException e)
        {
            _logger.error("Could not read 'class' config parameter", e);
            throw new CryptoException(SystemErrors.ERROR_CONFIG_READ,e);
        }
        
        //Instantiate factory and retrieve key + certificate
        try
        {
            AbstractSigningFactory signingFactory = 
                (AbstractSigningFactory)Class.forName(
                    sSigningFactory).newInstance();  
            
            signingFactory._configurationManager = configManager;
            signingFactory._eSection = eConfig;
            
            return signingFactory;
        }
        catch (InstantiationException e)
        {
            _logger.error("Could not instantiate signing factory with name: " 
                + sSigningFactory, e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }
        catch (IllegalAccessException e)
        {
            _logger.error(
                "Illegal Access when instantiating signing factory with name: " 
                + sSigningFactory, e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }
        catch (ClassNotFoundException e)
        {
            _logger.error("No signing factory found with name: " 
                + sSigningFactory, e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }  
    }
    
    /**
     * Start the signing factory.
     * @throws CryptoException
     */
    public abstract void start() throws CryptoException;
    
	/**
	 * Retrieve the private key.
	 * @return The private key of this OA Server.
	 * @throws CryptoException If retrieving fails
	 */
	public abstract PrivateKey getPrivateKey() throws CryptoException;
	
	/**
     * Retrieve the private key password.
     * @return The private key password of this OA Server.
     * @throws CryptoException If retrieving fails
     */
    public abstract String getPrivateKeyPassword() throws CryptoException;
    
    /**
     * Retrieve the private key alias.
     * @return The private key alias of this OA Server.
     * @since 1.4
     */
    public abstract String getAlias();
    
    /**
     * Retrieve all certificate aliases.
     * @return The certificate aliases of this OA Server.
     * @throws CryptoException If retrieving fails
     * @since 1.4
     */
    public abstract Enumeration<String> getAliases() throws CryptoException;
    
    /**
     * Retrieve the certificate.
     * @return The certificate of this OA Server.
     * @throws CryptoException If retrieving fails
     */
    public abstract Certificate getCertificate() throws CryptoException;
    
    /**
     * Retrieve an trusted certificate with a given alias.
     * @param sAlias The alias of the certificate.
     * @return The certificate of this OA Server.
     * @throws CryptoException If retrieving fails
     */
    public abstract Certificate getCertificate(
        String sAlias) throws CryptoException;
    
    /**
     * Return a X509 Certificate for to a given Certificate
     *
     * @param cert The certificate to be found.
     * @return alias of the certificate or <code>null</code> if non found.
     * @throws CryptoException If retrieval fails due to internal error.
     * @since 1.4
     */
    public abstract String getCertificateAlias(
        Certificate cert) throws CryptoException;
    
    /**
     * Retrieve a X509 Certificate alias according to a given properties.
     *
     * The serialNumber is optional and is ignored when <code>null</code>.
     * @param issuer The certificate issuer.
     * @param serialNumber The optiona serial number.
     * 
     * @return alias of the certificate or <code>null</code> if non found.
     * @throws CryptoException If retrieval fails due to internal error.
     * @since 1.4
     */
    public abstract String getAliasForX509Cert(
        String issuer, BigInteger serialNumber) throws CryptoException;
    
    /**
     * Retrieve the signing key store.
     * 
     * This could be another store than the trust store.
     * @return The keystore.
     * @since 1.4
     */
    public abstract KeyStore getKeyStore();   
    
}