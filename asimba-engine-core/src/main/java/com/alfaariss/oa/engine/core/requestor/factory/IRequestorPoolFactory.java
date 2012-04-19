/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
package com.alfaariss.oa.engine.core.requestor.factory;

import java.util.Collection;

import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.requestor.RequestorException;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;

/**
 * A factory interface for managing requestorPools.
 *
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public interface IRequestorPoolFactory
{   
	/**
	 * Retrieve the <code>RequestorPool</code> which contains 
     *  the given requestor.
	 * @param sRequestor The id of the requestor.
	 * @return The requestor pool containing the given requestor.
	 * @throws RequestorException if retrieval fails
	 */
	public RequestorPool getRequestorPool(String sRequestor) throws RequestorException;
   
	/**
	 * Retrieve the requestor with the given ID.
	 * @param sRequestor The id of the requestor.
	 * @return The requestor.
	 * @throws RequestorException if retrieval fails
	 */
	public IRequestor getRequestor(String sRequestor) throws RequestorException;

    /**
     * Checks if the supplied pool id exists.
     *
     * @param sPoolID The id of the pool
     * @return TRUE if the pool exists
     * @throws RequestorException if exists check fails
     */
    public boolean isPool(String sPoolID) throws RequestorException;

    /**
     * Returns all requestorpools (enabled and disabled).
     * @return An unmodifiable collection containing all requestor pools
     * @throws RequestorException
     * @since 1.5
     */
    public Collection<RequestorPool> getAllRequestorPools() throws RequestorException;
    
    /**
     * Returns all enabled requestorpools.
     * @return An unmodifiable collection containing all enabled requestor pools
     * @throws RequestorException if retrieval fails
     * @since 1.5
     */
    public Collection<RequestorPool> getAllEnabledRequestorPools() throws RequestorException;
    
    /**
     * Checks if the supplied requestor id exists.
     * @param sRequestorID The id of the requestor
     * @return TRUE if the requestor exists
     * @throws RequestorException if exist check fails
     * @since 1.5
     */
    public boolean isRequestor(String sRequestorID) throws RequestorException;
    
    /**
     * Returns all requestors (enabled and disabled).
     * @return An unmodifiable collection containing all requestors
     * @throws RequestorException if retrieval fails
     * @since 1.5
     */
    public Collection<IRequestor> getAllRequestors() throws RequestorException;
        
    /**
     * Returns all enabled requestors.
     * @return An unmodifiable collection containing all enabled requestors
     * @throws RequestorException if retrieval fails
     * @since 1.5
     */
    public Collection<IRequestor> getAllEnabledRequestors() throws RequestorException;
    
    
    /**
     * Retrieve a requestor.
     * <br>
     * The requestor that will be retrieved is the requestor with the given ID 
     * (as object) and it's type (column, parameter name, ...). It is only 
     * supported if the storage of the requestors also supports this. 
     * (see isRequestorIDSupported())
     * 
     * @param id The id of the requestor.
     * @param type The type of the ID, like column name or parameter name.
     * @return The requested requestor or NULL if not found.
     * @throws RequestorException If the requestor cannot be retrieved
     * @since 1.5
     */
    public IRequestor getRequestor(Object id, String type) throws RequestorException;
    
    /**
     * Checks if the supplied ID type is supported by the implementation.
     * 
     * @param type The type of the ID, like column name or parameter name.
     * @return TRUE if the ID type is supported.
     * @throws RequestorException If the support check cannot be performed.
     * @since 1.5
     */
    public boolean isRequestorIDSupported(String type) throws RequestorException;
    
}