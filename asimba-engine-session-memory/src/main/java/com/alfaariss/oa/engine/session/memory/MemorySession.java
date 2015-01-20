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
package com.alfaariss.oa.engine.session.memory;

import com.alfaariss.oa.api.persistence.IEntity;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.engine.core.session.AbstractSession;

/**
 * A simple session implementation which can be stored in memory.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class MemorySession extends AbstractSession 
{       
    private transient MemorySessionFactory _context;    
 
    /**
     * Create a new <code>MemorySession</code>.
     * @param context The context of this Session. 
     * @param requestorId The id of the requestor for which this authentication
     *  session is created. 
     */
    public MemorySession(MemorySessionFactory context, String requestorId)
    {
        super(requestorId);
        _context = context;  
    } 
      
    /**
     * @see IEntity#persist()
     */
    public void persist() throws PersistenceException
    {
        _context.persist(this);        
    }

    /**
     * Set a new Session ID.<br/>
     * <br/>
     * Note: default package private visibility, so JGroupsSessionFactory<br/> 
     * can set the Id but others can not.
     * 
     * @param id The new session ID.
     */
    void setId(String id)
    {
        _id = id;        
    }
}
