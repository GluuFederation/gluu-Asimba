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
package com.alfaariss.oa.api.persistence;

/**
 * An interface for persistence entities contexts.
 * @author EVB
 * @author Alfa & Ariss
 * @param <E> The entity type.
 *
 */
public interface IEntityManager<E extends IEntity> 
{

	/**
	 * Check if an entity with the given ID exists.
	 * @param id The id of the entity.
	 * @return <code>true</code> if an entity with the given id exists. 
	 * @throws PersistenceException 
	 */
	public boolean exists(Object id) throws PersistenceException;
	
	/**
	 * Retrieve the entity with the given id.
	 * @param id The id of the entity.
	 * @return The entity if found, otherwise <code>null</code>.
	 * @throws PersistenceException If retrieving fails.
	 */
	public E retrieve(Object id)
	  throws PersistenceException;
	
	/**
	 * Store or update the given entity in the storage.
	 * @param oEntity The entity to persist.
	 * @throws PersistenceException If persistance fails.
	 */
	public void persist(E oEntity) throws PersistenceException;

	/**
	 * Store or update several entities in the storage.
     * 
     *  Example for JDBC: 
     *  
     *  connection.setAutoCommit(false);
     *  PreparedStatement statement = 
     *  connection.prepareStatement("INSERT INTO the_entity VALUES(?, ?)");
     *  statement.setInt(1, 1);
     *  statement.setString(2, entity.name);
     *  statement.addBatch();
     *  statement.setInt(1, 2);
     *  statement.setString(2, entity.name);
     *  statement.addBatch();
     *  statement.setInt(1, 3);
     *  statement.setString(2, entity.name);
     *  statement.addBatch();
     *    int [] counts = statement.executeBatch();
     *  connection.commit();
     *  
	 * @param entities The entities to persist.
	 * @throws PersistenceException If persistance fails.
	 */
	public void persist(E[] entities) throws PersistenceException;
    

}