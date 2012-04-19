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
package com.alfaariss.oa.api.requestor;
import java.io.Serializable;
import java.util.Collections;
import java.util.Map;

import com.alfaariss.oa.api.IManagebleItem;

/**
 * An interface for OA requestors.
 *
 * Requestors are:
 * <ul>
 *  <li>Applications (SPs)</li>
 *  <li>Local OA Servers (IDPs)</li>  
 * </ul>
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public interface IRequestor extends IManagebleItem, Serializable 
{
    
    /**
     * Attribute name for adding the requestor object as attribute to a 
     * <code>Map</code>, request, session, or application.
     */
    public final static String REQUESTOR_ATTRIBUTE_NAME = "requestor";

	/**
	 * Retrieve the extended properties of this requestor.
	 * This collection should be properted by means of 
	 * {@link Collections#unmodifiableMap(Map)}.
	 * 
	 * @return Map The requestor properties.
	 */
	public Map getProperties();
	
	/**
     * Retrieve a single extended property value of this requestor.
	 * @param sName The property name.
     * @return Object The requestor property value.
     */
    public Object getProperty(String sName);
    
    /**
     * Check if a single extended property exists for this requestor.
     * @param sName The property name.
     * @return <code>true</code> if the property exists.
     */
    public boolean isProperty(String sName);
}