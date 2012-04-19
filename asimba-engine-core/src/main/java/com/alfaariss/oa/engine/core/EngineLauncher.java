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
package com.alfaariss.oa.engine.core;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.engine.core.configuration.ConfigurationManager;

/**
 * Initializes the OA {@link Engine} component.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class EngineLauncher 
{
    private static Log _logger;
    private static Engine _engine;
    private static Properties _pConfig;
    private ConfigurationManager _configurationManager;
    
	/**
	 * Creates the object.
	 * @throws OAException 
	 */
	public EngineLauncher() throws OAException
    {
        try
        {
            _logger = LogFactory.getLog(EngineLauncher.class); 
            _configurationManager = ConfigurationManager.getInstance();
            _engine = Engine.getInstance();
        }
        catch (Exception e)
        {
            _logger.error("Internal error while creating object", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
	}

	/**
	 * Starts the OA engine.
	 *
	 * Starts the configuration manager with the supplied properties.
     * If the file <code>[system property user.dir]/oa.prop</code> is found,
     * the supplied properties will be overwritten with the properties in the 
     * file.
	 * @param pConfig properties with the location of the configuration
	 * @throws OAException if start fails
	 */
	public void start(Properties pConfig) throws OAException
    {
        //TODO: Maybe the properties file must be stored, because they can be changed during a restart (MHO) 
        try
        {   if (_pConfig == null)
                _pConfig = new Properties();//don't overwrite the properties if this method is called again
            
            if (pConfig != null)
                _pConfig.putAll(pConfig);
            
            if (_pConfig.isEmpty())
            {
                Properties pSearchedConfig = getConfigProperties();
                if (pSearchedConfig != null)
                    _pConfig.putAll(pSearchedConfig);
            }
            
            _configurationManager.start(_pConfig);
            
            _engine.start(_configurationManager, null); //null is XML root tag
            
            _logger.info("Started EngineLauncher");
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Internal error during initialization", e);
            
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
	}
	
	/**
	 * Restarts the engine.
	 *
	 * Uses the supplied properties or if they are <code>null</code> the 
     * properties used during the start to restart the OA engine.
	 * @param pConfig properties with the location of the configuration
	 * @throws OAException if restart fails
	 */
	public void restart(Properties pConfig) throws OAException
    {
        Properties pRestartConfig = null;
        try
        {
            if (!_engine.isInitialized())
            {
                _logger.info("Engine is not started yet; Trying to start");
                start(pConfig);
            }
            else
            {
                pRestartConfig = _pConfig;
                
                if (pConfig != null)
                    pRestartConfig.putAll(pConfig);
                
                _configurationManager.stop();
                _configurationManager.start(pRestartConfig);
                
                _engine.restart(null);
                
                _logger.info("Restarted EngineLauncher");
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer("Internal error during restart ");
            if (pRestartConfig == null)
                sbError.append("without supplied configuration");
            else
            {
                sbError.append("with the following supplied configuration: ");
                sbError.append(pRestartConfig.toString());
            }
            _logger.error(sbError.toString(), e);
            
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
	}

	/**
	 * Stops the OA engine.
	 */
	public void stop()
    {
        if (_engine != null)
            _engine.stop();
        if (_configurationManager != null)
            _configurationManager.stop();
        
        _logger.info("Stopped EngineLauncher");
	}

    private Properties getProperties(File fConfig) throws OAException
    {
        Properties pConfig = new Properties();
        try
        {
            FileInputStream oFileInputStream = new FileInputStream(fConfig);
            pConfig.load(oFileInputStream);
            oFileInputStream.close();
        }
        catch (Exception e)
        {
            _logger.error("Can't load properties file: " + fConfig.toString(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
            
        return pConfig;
    }
    
    private Properties getConfigProperties() throws OAException
    {   
        _logger.debug("Search for 'oa.prop' as resource of the current thread context classloader");
        URL urlProperties = Thread.currentThread().getContextClassLoader().getResource("oa.prop");
        if (urlProperties != null)
        {
            String sProperties = urlProperties.getFile();
            _logger.debug("Found 'oa.prop' file in: " + sProperties);
            File fProperties = new File(sProperties);
            if (fProperties != null && fProperties.exists())
            {
                _logger.info("Updating configuration items with the items in: " + fProperties.getAbsolutePath());
                return getProperties(fProperties);
            }
            
            _logger.info("Could not resolve: " + fProperties.getAbsolutePath());
        }
        else
            _logger.info("No 'oa.prop' found as resource of the current thread context classloader");
        
        
        _logger.debug("Search for 'oa.prop' as resource of the classloader of the current class");
        urlProperties = EngineLauncher.class.getResource("oa.prop");
        if (urlProperties != null)
        {
            String sProperties = urlProperties.getFile();
            _logger.debug("Found 'oa.prop' file in: " + sProperties);
            File fProperties = new File(sProperties);
            if (fProperties != null && fProperties.exists())
            {
                _logger.info("Updating configuration items with the items in: " + fProperties.getAbsolutePath());
                return getProperties(fProperties);
            }
            
            _logger.info("Could not resolve: " + fProperties.getAbsolutePath());
        }
        else
            _logger.info("No 'oa.prop' found as resource of the classloader of the current class");
        
        
        _logger.debug("Search for 'oa.prop' as system resource of the static classloader");
        urlProperties = ClassLoader.getSystemResource("oa.prop");
        if (urlProperties != null)
        {
            String sProperties = urlProperties.getFile();
            _logger.debug("Found 'oa.prop' file in: " + sProperties);
            File fProperties = new File(sProperties);
            if (fProperties != null && fProperties.exists())
            {
                _logger.info("Updating configuration items with the items in: " + fProperties.getAbsolutePath());
                return getProperties(fProperties);
            }
            
            _logger.info("Could not resolve: " + fProperties.getAbsolutePath());
        }
        else
            _logger.info("No 'oa.prop' found as system resource of the static classloader");
        
        return null;
    }
}