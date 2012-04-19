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
package com.alfaariss.oa.api.configuration.handler;

import java.util.Properties;

import org.w3c.dom.Document;

import com.alfaariss.oa.api.configuration.ConfigurationException;

/**
 * Interface for all ConfigHandlers.
 * 
 * Configuration handlers can be used to read from and write to a 
 * physical storage.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public interface IConfigurationHandler 
{
    
    /**
     * Initialize the configuration.
     * 
     * @param pConfig The configuration handler properties.
     * @throws ConfigurationException Id initializing fails.
     */
    public void init(Properties pConfig) throws ConfigurationException;
    
	/**
	 * Read and parse the configuration.
     * 	 
	 * @return The configuration DOM Object.
	 * @exception ConfigurationException If parsing fails.
	 */
	public Document parseConfiguration() throws ConfigurationException;

	/**
	 * Saves the configuration.
	 * Writes the configuration to the physical storage. 
     * It will overwrite the existing configuration.
	 * 
	 * @param oConfigurationDocument The configuration document to save.
	 * @exception ConfigurationException If saving fails.
	 */
	public void saveConfiguration(Document oConfigurationDocument)
	  throws ConfigurationException;
}