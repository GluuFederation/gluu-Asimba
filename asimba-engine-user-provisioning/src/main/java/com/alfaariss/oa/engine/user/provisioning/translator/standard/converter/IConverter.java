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

import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;

/**
 * Interface for a converter object that can be used by the converter manager.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IConverter 
{

	/**
     * Starts the converter.
	 * @param oConfigurationManager the configuration manager
	 * @param eConfig converter configuration
	 * @throws UserException if starting fails
	 */
	public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws UserException;

	/**
     * Converts the given values.
     * 
	 * @param oValue the object that must be converted
	 * @return the converted object
	 */
	public Object convert(Object oValue);

	/**
     * Stops the converter.
     */
	public void stop();

}