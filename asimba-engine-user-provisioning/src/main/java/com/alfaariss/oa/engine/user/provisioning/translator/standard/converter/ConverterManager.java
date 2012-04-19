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
package com.alfaariss.oa.engine.user.provisioning.translator.standard.converter;

import java.util.Enumeration;
import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;

/**
 * Manager containing converters.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ConverterManager 
{
    private static String PACKAGENAME = ConverterManager.class.getPackage().getName();
    private Log _logger;
    private Hashtable<String, IConverter> _htConverters;
   
	/**
     * Creates the object.
	 * @param oConfigurationManager the configuration manager
	 * @param eConfig the configuration section with configuration of this object
	 * @throws UserException if converting fails
	 */
	public ConverterManager(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws UserException
    {
        _htConverters = new Hashtable<String, IConverter>();
        try
        {
            _logger = LogFactory.getLog(ConverterManager.class);
            
            Element eConverter = oConfigurationManager.getSection(eConfig, "converter");
            if(eConverter == null)
            {
                _logger.error("No 'converter' section found in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            while (eConverter != null)
            {
                String sConverterID = oConfigurationManager.getParam(eConverter, 
                    "id");
                if (sConverterID == null)
                {
                    _logger.error("No 'id' parameter found in 'converter' section");
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (_htConverters.containsKey(sConverterID))
                {
                    StringBuffer sbError = new StringBuffer(
                        "The converter with id '");
                    sbError.append(sConverterID);
                    sbError.append("' is not unique");
                    
                    _logger.error(sbError.toString());
                    
                    throw new UserException(SystemErrors.ERROR_INIT);
                }
                
                String sConverterClass = oConfigurationManager.getParam(
                    eConverter, "class");
                if (sConverterClass == null)
                {
                    _logger.error(
                        "No 'class' parameter found in 'converter' section with id: " 
                        + sConverterID);
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (sConverterClass.startsWith("."))
                    sConverterClass = PACKAGENAME + sConverterClass;
                
                Class oConverterClass = null;
                try
                {
                    oConverterClass = Class.forName(sConverterClass);
                }
                catch (Exception e)
                {
                    _logger.error("No 'class' found with name: " + sConverterClass, e);
                    throw new UserException(SystemErrors.ERROR_INIT);
                }
                
                IConverter oConverter = null;
                try
                {
                    oConverter = (IConverter)oConverterClass.newInstance();
                }
                catch (Exception e)
                {
                    _logger.error(
                        "Could not create an 'IConverter' instance of the configured 'class' found with name: " 
                        + sConverterClass, e);
                    throw new UserException(SystemErrors.ERROR_INIT);
                }
                
                oConverter.start(oConfigurationManager, eConverter);
                
                _htConverters.put(sConverterID, oConverter);
                
                eConverter = oConfigurationManager.getNextSection(eConverter);
            }
        }
        catch (UserException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not initialize object", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
	}

	/**
	 * Verifies whether the converter with the supplied id exists.
     * @param sConverterID the id of the converter
	 * @return TRUE if the converter exists
	 */
	public boolean existsConverter(String sConverterID)
    {
		return _htConverters.containsKey(sConverterID);
	}

	/**
	 * Returns the converter with the supplied id.
	 * @param id the converter id
	 * @return the IConverter object or <code>null</code> if not exists
	 */
	public IConverter getConverter(String id)
    {
		return _htConverters.get(id);
	}
    
    /**
     * Stops the converter manager. 
     */
    public void stop()
    {
        Enumeration enumConverters = _htConverters.elements();
        while (enumConverters.hasMoreElements())
        {
            IConverter oIConverter = (IConverter)enumConverters.nextElement();
            if (oIConverter != null)
                oIConverter.stop();
        }
    }
}