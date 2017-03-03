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
package com.alfaariss.oa.util.storage.factory;

import java.security.SecureRandom;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.storage.IStorageFactory;
import com.alfaariss.oa.util.storage.StorageException;
import com.alfaariss.oa.util.storage.clean.Cleaner;

/**
 * Abstract base class for session and TGT factories.
 * 
 * DD The storage factory is implemented conform the AbstractFactory pattern.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public abstract class AbstractStorageFactory implements IStorageFactory
{  
    /** UTF-8 */
    protected final static String CHARSET = "UTF-8";
    /** secure random */
    protected SecureRandom _random;
    /** configuration manager */
    protected IConfigurationManager _configurationManager;
    /** configuration section */
    protected Element _eConfig;
    /** Maximum count of unexpired objects in memory, 0=infinity */
    protected long _lMax;
    /** expire time */
    protected long _lExpiration;
    /** cleaner thread */
    protected Thread _tCleaner;
    /** cleaner */
    protected Cleaner _oCleaner;
    
    /** system logger */
    private static Log _logger = LogFactory.getLog(
        AbstractStorageFactory.class);
    private long _lInterval;   
        
    /**
     * Constructor.
     * Use createInstance() instead.  
     */
    public AbstractStorageFactory()
    {
        //do nothing
    }

    /**
     * Create and start the <code>AbstractSessionFactory</code>.
     * @param oConfigurationManager The configuration manager.
     * @param eConfig The configuration section.
     * @param random The secure pseudo random generator.
     * @return The created storage factory
     * @throws OAException If starting fails.
     */
    public static IStorageFactory createInstance(
        IConfigurationManager oConfigurationManager, 
        Element eConfig, SecureRandom random) throws OAException
    {

        if(oConfigurationManager == null)
            throw new IllegalArgumentException(
                "Suplied configuration manager is empty");
        if(eConfig == null)
            throw new IllegalArgumentException("Suplied section is empty");
        if(random == null)
            throw new IllegalArgumentException("Suplied securerandom is empty");

        String sClass = oConfigurationManager.getParam(eConfig, "class");
        if (sClass == null)
        {
            _logger.error(
                "Storage Factory implementation class parameter not found");
            throw new StorageException(SystemErrors.ERROR_CONFIG_READ);
        }
        AbstractStorageFactory factory = loadFactory(sClass); 
        factory._random = random;   
        factory._configurationManager = oConfigurationManager;
        factory._eConfig = eConfig;
        
        //Get interval
        String sInterval = oConfigurationManager.getParam(eConfig, "interval");
        if (sInterval == null)
        {
            _logger.error("No 'interval' item found in configuration");
            throw new StorageException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        try
        {
            factory._lInterval = Long.parseLong(sInterval);
            if(factory._lInterval <= 0)
            {
                _logger.info("Storage cleaner interval less then or equal to zero, cleaning is disabled.");
            }
            else
            {
                factory._lInterval *= 1000;
                //Create cleaner
                factory._oCleaner = new Cleaner(factory._lInterval, factory, _logger);
                
                factory._tCleaner = new Thread(factory._oCleaner);
                
                String sOrigName = factory._tCleaner.getName();
                StringBuffer sbName = new StringBuffer(factory.getClass().getName());
                sbName.append("(");
                sbName.append(sOrigName);
                sbName.append(")");
                factory._tCleaner.setName(sbName.toString());
            }
        }  
        catch(NumberFormatException e)
        {
            _logger.error("Invalid 'interval' configuration" ,e);
            throw new StorageException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        //get expiration timeout
        String sExpiration = oConfigurationManager.getParam(eConfig, "expire");
        if (sExpiration == null)
        {
            _logger.error("No 'expire' item found in configuration");
            throw new StorageException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        try
        {
            factory._lExpiration = Long.parseLong(sExpiration);
            if(factory._lExpiration <= 0)
            {
                _logger.error("Expire time less then or equal to zero: " + sExpiration);
                throw new StorageException(SystemErrors.ERROR_CONFIG_READ); 
            }
            factory._lExpiration *= 1000;
        } 
        catch(NumberFormatException e)
        {
            _logger.error("Invalid 'expire' configuration: " + sExpiration, e);
            throw new StorageException(SystemErrors.ERROR_CONFIG_READ, e); 
        }
        
        //Get maximum
        String sMax = oConfigurationManager.getParam(eConfig, "max");
        if(sMax != null) //max configured
        {
            try
            {
                factory._lMax = Long.parseLong(sMax);    
                if(factory._lMax <= 0)
                {
                    _logger.error("Expire time less then or equal to zero: " + sMax);
                    throw new StorageException(SystemErrors.ERROR_CONFIG_READ); 
                }
            }       
            catch(NumberFormatException e)
            {
                _logger.error("Invalid 'max' configuration: " + sMax, e);
                throw new StorageException(SystemErrors.ERROR_CONFIG_READ, e);
            }
        }
        else
        {
            _logger.info("No maximum configured");
            factory._lMax = -1;
        }
        factory.start();
        return factory;
    }
    
    /**
     * Stop the factory and cleaner if initialized.
     */
    public void stop()
    {
        if (_oCleaner != null)
            _oCleaner.stop();
        
        if (_tCleaner != null)
            _tCleaner.interrupt();              
    }
    
    //  Load the factory class
    private static AbstractStorageFactory loadFactory(String sClass) throws StorageException
    {
        AbstractStorageFactory factory = null;
        try
        {
            factory = (AbstractStorageFactory)Class.forName(sClass).newInstance();           
        }
        catch (InstantiationException e)
        {
            _logger.error("Can't create an instance of the factory: " 
                + sClass, e);
            throw new StorageException(SystemErrors.ERROR_CONFIG_READ, e);
        }
        catch (IllegalAccessException e)
        {
            _logger.error(
                "Configured factory class can't be accessed: " 
                + sClass, e);
            throw new StorageException(SystemErrors.ERROR_CONFIG_READ, e);
        }
        catch (ClassNotFoundException e)
        {
            _logger.error(
                "Configured factory class doesn't exist: " 
                + sClass, e);
            throw new StorageException(SystemErrors.ERROR_CONFIG_READ, e);
        }
        catch (ClassCastException e)
        {
            _logger.error(
                "Configured session factory class isn't of type 'IStorageFactory': " 
                + sClass, e);
            throw new StorageException(SystemErrors.ERROR_CONFIG_READ, e);
        }  
        return factory;
    }
}