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
package com.alfaariss.oa.api.configuration;


import java.util.List;

import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.handler.IConfigurationHandler;

/**
 * Interface for a common configuration manager.
 * 
 * The <code>ConfigurationManager</code> offers an interface to the 
 * configuration, which can be used by all OA components. 
 * 
 * It's set up like a factory to resolve the right 
 * <code>IConfigurationHandler</code> to read and write the configuration 
 * from several sources.

 * @author Alfa & Ariss
 * @author EVB 
 *
 */
public interface IConfigurationManager 
{
  
	/**
	 * Initialize the <code>ConfigurationManager</code>.
	 *
	 * <ul>
     *  <li>Set logger</li>
     *  <li>Set configuration handler</li>
     *  <li>Parse configuration</li>
     * </ul> 
     * 
	 * @param handler The configuration handler.
	 * @throws ConfigurationException If configuration parsing fails.
     * @see IConfigurationHandler#parseConfiguration()
	 */
	public void init(IConfigurationHandler handler)
	  throws ConfigurationException;
    
	/**
	 * Saves the configuration.
	 *
	 * Writes the configuration to the physical storage. It will overwrite the
     * existing configuration.
	 * @throws ConfigurationException Id save fails.
	 */
	public void saveConfiguration() throws ConfigurationException;
	/**
	 * Retrieves a config section by its type and id.
	 *
	 * @param eRootSection The root section.
	 * @param sSectionType The type of the section (name).
	 * @param sSectionID The id of the section.
	 * @return The section, or <code>null</code> if section does not exist.
	 */
	public  Element getSection(Element eRootSection, 
        String sSectionType, String sSectionID);
   
	/**
	 * Retrieves a config section by its type.
	 *
	 * @param eRootSection The root section.
	 * @param sSectionType The type of the section (name).
	 * @return The section, or <code>null</code> if section does not exist.
	 */
	public Element getSection(Element eRootSection, String sSectionType);

	/**
	 * Creates a new configuration section (empty tag) with section 
     * type as its name.
	 *
	 * @param sSectionType The type of the section (name).
	 * @return The new section.
	 * @throws ConfigurationException
	 */
	public Element createSection(String sSectionType)
	  throws ConfigurationException;

	
	/**
	 * Add a new configuration section to the configuration.
	 *
	 * @param eRootSection The root section.
	 * @param eNewSection The new section.
	 * @throws ConfigurationException
	 */
	public void setSection(
        Element eRootSection, Element eNewSection) throws ConfigurationException;
	    
	/**
	 * Retrieve a configuration parameter value.
	 *
	 * Retrieves the value of the config parameter from the config section 
     * that is supplied.
	 * @param eSection The base section.
	 * @param sName The parameter name.
	 * @return The parameter value.
	 * @throws ConfigurationException If retrieving fails.
	 */
	public String getParam(Element eSection, String sName)
	    throws ConfigurationException;
	
	/**
	 * Retrieve one or more configuration parameter values.
     *
     * Retrieves all values of the config parameters from the config 
     * section that is supplied.
	 *
	 * @param eSection The base section.
	 * @param sParamName The parameter name.
	 * @return List with values of all parameters or NULL if not found.
	 * @throws ConfigurationException If retrieval fails.
	 * @since 1.5
	 */
	public List<String> getParams(Element eSection, String sParamName) 
	    throws ConfigurationException;
    
	/**
	 * Set a configuration parameter value.
	 *
	 * Puts a new parameter into the given section like.
	 * @param eSection The base section.
	 * @param sName The parameter name.
	 * @param sValue The parameter value.
	 * @param bMandatory Mandatory parameters are set as attribute, 
     *  none mandatory as sub-element.
	 * @throws ConfigurationException If setting fails.
	 */
	public void setParam(Element eSection, String sName, 
        String sValue, boolean bMandatory) throws ConfigurationException;
    
	/**
	 * Resolve the next section.
	 *
	 * Resolve the next section (XML tag) which has the same type as the 
     * supplied section. The sections must be located in the same
     * root section (root tag).
	 * @param eSection The base section.
	 * @return The next section if available, otherwise <code>null</code>.
	 */
	public Element getNextSection(Element eSection);
   
	/**
	 * Remove a configuration section.
	 *
	 * Removes the section (XML tag) from the supplied root section which 
     * has the type that is supplied.
	 * @param eRootSection The base section.
	 * @param sName The section name.
	 * @return <code>true</code> if section is found and deleted, otherwise
     *  <code>false</code>.
	 * @throws ConfigurationException if removal fails.
	 */
	public boolean removeSection(
        Element eRootSection, String sName) throws ConfigurationException;
    
	/**
	 * Remove a configuration section.
	 *
	 * Removes the section (XML tag) from the supplied root section which has 
     * the type and the ID that is supplied. 
     * The ID must be an XML attribute like: id=[id]
	 * @param eRootSection The root section.
	 * @param sName The section name.
	 * @param sSectionID The section id
	 * @return <code>true</code> if section is found and deleted, otherwise
     *  <code>false</code>.
	 * @throws ConfigurationException
	 */
	public boolean removeSection(Element eRootSection, 
        String sName, String sSectionID) throws ConfigurationException;
}