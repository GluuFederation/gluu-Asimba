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
package com.alfaariss.oa.api.attribute;

import java.io.Serializable;
import java.util.Enumeration;

/**
 * Standard interface for OA (user) attributes.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public interface IAttributes extends Serializable
{
	/**
	 * Retrieve an attribute value.
	 * @param sName The attribute name.
	 * @return The attribute with the given name.
	 */
	public Object get(String sName);
    
    /**
     * Retrieve all attribute names.
     * @return an <code>Enumeration</code> with all attribute names
     */
    public Enumeration<?> getNames();

	/**
	 * Add or update an attribute.
     * 
     * Before setting an attribute the caller can check the existence
     * of the attribute by calling <code>contains()</code>.
	 * @param sName The attribute name.
	 * @param oValue The attribute value.
     * @see IAttributes#contains(String)
	 */
	public void put(String sName, Object oValue);    
       
    /**
     * Check if an attribute exists.
     * @param sName The attribute name.
     * @return <code>true</code> if these attributes contain the given attribute.
     */
    public boolean contains(String sName);

	/**
	 * Remove an attribute.
	 * @param sName The attribute name.
	 */
	public void remove(String sName);  
    
    /**
     * Returns the size of the object. 
     * @return an int indicating the count
     */
    public int size();
        
    /**
     * Add or update an attribute.
     * 
     * Before setting an attribute the caller can check the existence
     * of the attribute by calling <code>contains()</code>.
     * @param sName The attribute name.
     * @param sFormat The format of the attribute or NULL if not available.
     * @param oValue The attribute value.
     * @since 1.5
     */
    public void put(String sName, String sFormat, Object oValue);    
    
    /**
     * Returns the format of the attribute. 
     * @param sName The name of the attribute.
     * @return The attribute format or NULL if not available.
     * @since 1.5
     */
    public String getFormat(String sName);
    
    /**
     * Set the format of the attribute.
     * @param sName The name of the attribute.
     * @param sFormat The format of the attribute.
     * @since 1.5
     */
    public void setFormat(String sName, String sFormat);
    
    /**
     * Removes the format of the attribute.
     * @param sName The name of the attribute.
     * @since 1.5
     */
    public void removeFormat(String sName);
}