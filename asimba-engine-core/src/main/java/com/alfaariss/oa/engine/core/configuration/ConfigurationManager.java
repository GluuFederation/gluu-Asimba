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
package com.alfaariss.oa.engine.core.configuration;

import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.handler.IConfigurationHandler;

/**
 * Wrapper around the ConfigurationManager from the utility package. 
 * 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ConfigurationManager extends com.alfaariss.oa.util.configuration.ConfigurationManager 
{
    private static ConfigurationManager _configurationManager;
    private Log _logger;
    
    /**
     * Returns always the same instance of the configuration manager.
     * Works according to the Singleton design pattern. 
     * @return always the same configuration manager instance
     */
    public static ConfigurationManager getInstance()
    {
        if (_configurationManager == null)
            _configurationManager = new ConfigurationManager();
            
        return _configurationManager;
    }
    /**
	 * Initializes the ConfigurationManager with the supplied properties.
	 * @param pConfig configuration properties containing the location of the configuration.
	 * @throws OAException 
	 */
	public void start(Properties pConfig) throws OAException
    {
        try
        {
            if (pConfig == null)
            {
                _logger.debug("The configuration properties object is NULL");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            String sHandlerClass = pConfig.getProperty("configuration.handler.class");
            if (sHandlerClass == null)
            {
                _logger.error("Property with name 'configuration.handler.class' not found");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Class cHandler = null;
            try
            {
                cHandler = Class.forName(sHandlerClass);
            }
            catch (Exception e)
            {
                _logger.error("Class doesn't exist: " + sHandlerClass, e);
                throw new OAException(SystemErrors.ERROR_INIT, e);
            }

            IConfigurationHandler oConfigurationHandler = null;
            try
            {
                oConfigurationHandler = (IConfigurationHandler)cHandler.newInstance();
            }
            catch(Exception e)
            {
                _logger.error("Configured class isn't of type IConfigurationHandler: " + sHandlerClass, e);
                throw new OAException(SystemErrors.ERROR_INIT, e);
            }
            
            oConfigurationHandler.init(pConfig);
            
            super.init(oConfigurationHandler);
            
            _logger.info("Configuration initialized");
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during start", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
	}
    
	/**
	 * Stops the configuration manager.
	 */
	public void stop()
    {
        //Nothing to do here
	}
    /**
     * Creates the object.
     */
    private ConfigurationManager()
    {
        _logger = LogFactory.getLog(ConfigurationManager.class);
    }

}