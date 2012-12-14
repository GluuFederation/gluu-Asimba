/*
 * * Asimba - Serious Open Source SSO
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
 * * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
 */
package com.alfaariss.oa.engine.session.jdbc;

import com.alfaariss.oa.api.persistence.IEntity;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.engine.core.attribute.SessionAttributes;
import com.alfaariss.oa.engine.core.session.AbstractSession;

/**
 * An Session implementation which can be added to a JDBC storage.
 *
 * Uses the OA persistence API.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class JDBCSession extends AbstractSession
{   
	//The persistance context    
    private transient JDBCSessionFactory _context;   
      
    /**
     * Create a new empty <code>JDBCSession</code>.
     * @param context The session context.
     * @param requestorId 
     */
    public JDBCSession(JDBCSessionFactory context, String requestorId)
    {
        super(requestorId);
        _context = context;  
    } 

	/**
	 * Persist the session using the 
     *  {@link JDBCSessionFactory#persist(JDBCSession)} method.
	 * @see IEntity#persist()
	 */
	public void persist()
	  throws PersistenceException
    {
        _context.persist(this);
	}
    
    /**
     * Set a new session id.
     * @param id The new id.
     */
    void setId(String id)
    {
        _id = id;
    }
    
    /**
     * Set a new Session expiration time.
     * @param expirationTime The new expiration time.
     */
    void setTgtExpTime(long expirationTime)
    {
        _lExpireTime = expirationTime;   
    }
    
    /**
     * Set a new set of attributes.
     * @param expirationTime The new expiration time.
     */
    void setAttributes(SessionAttributes attributes)
    {
        _attributes = attributes;
    }
}