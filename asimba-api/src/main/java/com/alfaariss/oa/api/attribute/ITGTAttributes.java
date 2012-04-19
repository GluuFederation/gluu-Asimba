/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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
 * Standard interface for TGT scope attributes.
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.3
 */
public interface ITGTAttributes extends Serializable
{
	/**
	 * Retrieve an attribute value.
     * @param oClass Class object
	 * @param sName The attribute name.
	 * @return The attribute with the given name.
	 */
	public Object get(Class<?> oClass, String sName);
    
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
	 * @param oClass Class object
	 * @param sName The attribute name.
	 * @param oValue The attribute value.
	 */
	public void put(Class<?> oClass, String sName, Object oValue);    
       
	/**
     * Add or update an attribute.
     * 
     * Before setting an attribute the caller can check the existence
     * of the attribute by calling <code>contains()</code>.
     * @param oClass Class object
	 * @param sID The component id.
     * @param sName The attribute name.
     * @param oValue The attribute value.
     */
    public void put(Class<?> oClass, String sID, String sName, Object oValue);    
    
    /**
     * Check if an attribute exists.
     * @param oClass Class object
     * @param sName The attribute name.
     * @return <code>true</code> if these attributes contain the given attribute.
     */
    public boolean contains(Class<?> oClass, String sName);

	/**
	 * Remove an attribute.
     * @param oClass Class object
	 * @param sName The attribute name.
	 */
	public void remove(Class<?> oClass, String sName);  
    
    /**
     * Returns the size of the object. 
     * @return an int indicating the count
     */
    public int size();
    
    /**
     * Retrieve an attribute value.
     * @param oClass Class object
     * @param sID The component id.
     * @param sName The attribute name.
     * @return The attribute with the given name.
     */
    public Object get(Class<?> oClass, String sID, String sName);
    
    /**
     * Check if an attribute exists.
     * @param oClass Class object
     * @param sID The component id.
     * @param sName The attribute name.
     * @return <code>true</code> if these attributes contain the given attribute.
     */
    public boolean contains(Class<?> oClass, String sID, String sName);
    
    /**
     * Remove an attribute.
     * @param oClass Class object
     * @param sID The component id.
     * @param sName The attribute name.
     */
    public void remove(Class<?> oClass, String sID, String sName);  

}