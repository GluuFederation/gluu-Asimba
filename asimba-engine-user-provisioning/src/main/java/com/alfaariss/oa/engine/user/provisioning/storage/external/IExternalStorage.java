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
package com.alfaariss.oa.engine.user.provisioning.storage.external;

import java.util.Hashtable;
import java.util.List;

import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.storage.IStorage;

/**
 * Interface for external storages.
 * 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IExternalStorage extends IStorage
{
   
	/**
     * Returns the specified field.
	 * @param id the unique id for which the field exists
	 * @param field the field name
	 * @return The field value as <code>Object</code>
	 * @throws UserException if the retrieval fails
	 */
	public Object getField(String id, String field) throws UserException;
    
    
    /**
     * Returns all specified fields.
     * @param id the unique id for which the field exists
     * @param fields the field names
     * @return A <code>Hashtable</code> containing the field name 
     *  (key) and his value (value) 
     * @throws UserException if retrieval fails
     */
    public Hashtable<String, Object> getFields(
        String id, List<String> fields) throws UserException;
}