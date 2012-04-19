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
package com.alfaariss.oa.engine.authentication.configuration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.authentication.AuthenticationException;
import com.alfaariss.oa.engine.core.authentication.AuthenticationMethod;

/**
 * The authentication method based on configuration items.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ConfigurationMethod extends AuthenticationMethod
{
    private static final long serialVersionUID = -8798513876097599670L;
    private static Log _logger;
    
    /**
     * Creates a method object.
     *
     * Creates the method object by reading the required information from the 
     * configuration file.
     * @param oConfigurationManager The configuration manager where the 
     * configuration can be read from.
     * @param eConfig the configuration section with the configuration needed 
     * for this method.
     * @throws AuthenticationException
     */
    public ConfigurationMethod(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws AuthenticationException
    {
        super();
        try
        {
            _logger = LogFactory.getLog(ConfigurationMethod.class);

            _sID = oConfigurationManager.getParam(eConfig, "id");
            if (_sID == null)
            {
                _logger.error("No 'id' item in 'profile' section found in configuration");
                throw new AuthenticationException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        catch (AuthenticationException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new AuthenticationException(SystemErrors.ERROR_INTERNAL);
        }
    }

}
