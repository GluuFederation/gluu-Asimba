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

import javax.crypto.SecretKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.storage.clean.ICleanable;
import com.alfaariss.oa.engine.core.crypto.CryptoException;
import com.alfaariss.oa.util.storage.clean.Cleaner;

/**
 * Abstract factory to be used for key providers.
 *
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public abstract class AbstractCipherFactory implements ICleanable
{
    /** system logger */
    private static Log _logger = LogFactory.getLog(AbstractCipherFactory.class);
    /**
     * The key that is used for the default key. 
     * (i.e. the key that is used when no parameter ID is found in 
     * the request for the key
     */
    protected static final String DEFAULT_KEY = "default_key";
    /** cleaner thread */
    protected Thread _tCleaner;
    /** configuration manager */
    protected IConfigurationManager _configurationManager;
    /** configuration section */
    protected Element _eCipherFactorySection;
    /** expire time */
    protected long _lExpiration;
    
    private long _lInterval;
    private Cleaner _oCleaner;
    
    /**
     * Create a new <code>AbstractCipherFactory</code>.
     */
    public AbstractCipherFactory()
    {
    }
    
    /**
     * Create and start the <code>AbstractCipherFactory</code>.

     * @param configManager
     * @param eCipherFactorySection
     * @return The created cipher factory 
     * @throws CryptoException
     */
    public static AbstractCipherFactory createInstance(
        IConfigurationManager configManager, Element eCipherFactorySection) throws CryptoException
    {        
        String sCipherFactory = null;
        if(configManager == null)
            throw new IllegalArgumentException(
                "Supplied configuration manager is empty");
        if(eCipherFactorySection == null)
            throw new IllegalArgumentException("Supplied section is empty");
        try
        {
            try
            {
                sCipherFactory = configManager.getParam(
                    eCipherFactorySection, "class");
            }
            catch (ConfigurationException e)
            {
                _logger.error("Could not read 'class' config parameter", e);
                throw new CryptoException(SystemErrors.ERROR_CONFIG_READ,e);
            }
            
            if(sCipherFactory == null)
            {        
                _logger.error("Could not retrieve 'class' config parameter");
                throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            AbstractCipherFactory cipherFactory = 
                (AbstractCipherFactory)Class.forName(sCipherFactory).newInstance();
            cipherFactory._configurationManager = configManager;
            cipherFactory._eCipherFactorySection = eCipherFactorySection;
            
            //get expiration timeout
            String sExpiration;
            try
            {
                sExpiration = configManager.getParam(eCipherFactorySection, "expire");
            }
            catch (ConfigurationException e)
            {
                _logger.error("Could not read 'expire' config parameter", e);
                throw new CryptoException(SystemErrors.ERROR_CONFIG_READ,e);
            }
            try
            {
                cipherFactory._lExpiration = Long.parseLong(sExpiration);
                if(cipherFactory._lExpiration <= 0)
                {
                    _logger.debug("NumberFormatException when parsing: " + sExpiration);
                    throw new NumberFormatException("Less then or equeal to zero");
                }
                cipherFactory._lExpiration *= 1000;
            } 
            catch(NumberFormatException e)
            {
                _logger.error("Invalid 'expire' configuration: " + sExpiration, e);
                throw new CryptoException(SystemErrors.ERROR_CONFIG_READ, e);
            }
            
            //Get interval
            String sInterval;
            try
            {
                sInterval = configManager.getParam(eCipherFactorySection, "interval");
            }
            catch (ConfigurationException e)
            {
                _logger.error("Could not read 'interval' config parameter", e);
                throw new CryptoException(SystemErrors.ERROR_CONFIG_READ,e);
            }
            try
            {
                cipherFactory._lInterval = Long.parseLong(sInterval);
                if(cipherFactory._lInterval <= 0)
                {
                    _logger.info(
                    "Storage cleaner interval less then or equal to zero, cleaning is disabled");
                }
                else
                {
                    cipherFactory._lInterval *= 1000;
                    //Create cleaner
                    cipherFactory._oCleaner = new Cleaner(cipherFactory._lInterval, 
                        cipherFactory, _logger);
                    
                    cipherFactory._tCleaner = new Thread(cipherFactory._oCleaner);
                    
                    String sOrigName = cipherFactory._tCleaner.getName();
                    StringBuffer sbName = new StringBuffer(cipherFactory.getClass().getName());
                    sbName.append("(");
                    sbName.append(sOrigName);
                    sbName.append(")");
                    cipherFactory._tCleaner.setName(sbName.toString());
                }
            }  
            catch(NumberFormatException e)
            {
                _logger.error("Invalid 'interval' configuration: " + sInterval,e);
                throw new CryptoException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            
            return cipherFactory;            
        }        
        catch (InstantiationException e)
        {
            _logger.error("Could not instantiate cipher factory with name: " 
                + sCipherFactory, e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }
        catch (IllegalAccessException e)
        {
            _logger.error(
                "Illegal Access when instantiating cipher factory with name: " 
                + sCipherFactory, e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }
        catch (ClassNotFoundException e)
        {
            _logger.error("No cipher factory found with name: " 
                + sCipherFactory, e);
            throw new CryptoException(SystemErrors.ERROR_INIT, e);
        }
    }
    
    /**
     * Start the <code>ICipherFactory</code>.    
     * @throws OAException If starting fails.
     */
    public abstract void start() throws OAException;
    
    /**
     * Generate or restore a secret key.
     *
     * In redundant environments this method will look for a stored key. 
     * If no such key exists it will generate a new one and store this to the 
     * persistence context.  
     * @param sCipherAlgorithm  The cipher algorithm to be used.
     * @param sCipherProvider  The provider to be used.
     * @return SecretKey The generated key.
     * @throws CryptoException If generating or restoring the key fails.
     */
    public abstract SecretKey getSecretKey(String sCipherAlgorithm, 
        String sCipherProvider) throws CryptoException;
    
    /**
     * Generate or restore a secret key with a specific name.
     *
     * In redundant environments this method will look for a stored key. 
     * If no such key exists it will generate a new one and store this to the 
     * persistance context.
     *
     * @param sCipherAlgorithm  The cipher algorithm to be used.
     * @param sCipherProvider  The provider to be used.
     * @param sName The name of the key requested
     * 
     * @return SecretKey The generated key.
     * @throws CryptoException If generating or restoring the key fails.
     */
    public abstract SecretKey getSecretKey(String sCipherAlgorithm, 
        String sCipherProvider, String sName) throws CryptoException;
    
    /**
     * Stop the Cipher Factory</code>.
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public void stop()
    {
        if (_oCleaner != null)
            _oCleaner.stop();
        
        if (_tCleaner != null)
            _tCleaner.interrupt();
    } 

}
