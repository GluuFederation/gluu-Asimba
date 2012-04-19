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
package com.alfaariss.oa.engine.user.provisioning.translator.standard.common;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.translator.standard.converter.ConverterManager;
import com.alfaariss.oa.engine.user.provisioning.translator.standard.converter.IConverter;

/**
 * A profile item.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ProfileItem
{
    private static Log _logger;
    private String _sDefault;
    private String _sField;
    private IConverter _oConverter;
    
    /**
     * Creates the object.
     * @param oConfigurationManager the configuration manager.
     * @param eConfig the configuration section containing the configuration 
     *  of this object
     * @param oConverterManager the converter manager
     * @throws UserException if creation fails
     */
    public ProfileItem(IConfigurationManager oConfigurationManager, 
        Element eConfig, ConverterManager oConverterManager) throws UserException
    {
        try
        {
            _logger = LogFactory.getLog(ProfileItem.class);
            
            _sDefault = oConfigurationManager.getParam(eConfig, "default");
            if (_sDefault == null)
                _logger.info("No optional 'default' configured");
            
            _sField = oConfigurationManager.getParam(eConfig, "field");
            if (_sField == null)
                _logger.info("No optional 'field' configured");
            
            String sConverterId = oConfigurationManager.getParam(
                eConfig, "converter");
            if (sConverterId == null)
                _logger.info("No optional 'converter' configured");
            else 
            {
                if (oConverterManager == null)
                {
                    _logger.error("Could not load configured 'converter', because Converter Manager is not available");
                    throw new UserException(SystemErrors.ERROR_INIT);
                }
                
                _oConverter = oConverterManager.getConverter(sConverterId);
                if (_oConverter == null)
                {
                    _logger.error("Configured 'converter' doesn't exist: " 
                        + sConverterId);
                    throw new UserException(SystemErrors.ERROR_INIT);
                }
            }            
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Could not create object", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * @return the default value or <code>null</code> if not configured
     */
    public String getDefault()
    {
        return _sDefault;
    }
    
    /**
     * @return the converter id or <code>null</code> if not configured
     */
    public IConverter getConverter()
    {
        return _oConverter;
    }
    
    /**
     * @return the field or <code>null</code> if not configured
     */
    public String getField()
    {
        return _sField;
    }

}
