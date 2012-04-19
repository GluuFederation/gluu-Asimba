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
package com.alfaariss.oa.engine.user.provisioning.translator.standard.converter.exist;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.translator.standard.converter.IConverter;

/**
 * Converts a value on its existence.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ExistConverter implements IConverter 
{
    private static Log _logger;
    
	/**
	 * Creates the object.
	 */
	public ExistConverter()
    {
        _logger = LogFactory.getLog(ExistConverter.class);
	}
    
    /**
     * Starts the object.
     * @see IConverter#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws UserException
    {
        //do nothing
    }
    
	/**
	 * Converts the value to a boolean value.
	 * @see IConverter#convert(java.lang.Object)
	 */
	public Object convert(Object oValue)
    {
        if (oValue == null)
            return Boolean.FALSE;
        
        if (!(oValue instanceof String))
        {
            _logger.debug("Not a String: " + oValue);
            throw new IllegalArgumentException("Not a String: " + oValue);
        }
        
        String sValue = (String)oValue;
        if (sValue.length() > 0)
            return Boolean.TRUE;
		return Boolean.FALSE;
	}

    /**
	 * Stops the object.
	 * @see IConverter#stop()
	 */
	public void stop()
    {
	    //do nothing
	}

}