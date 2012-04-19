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
package com.alfaariss.oa.engine.core.session.factory;

import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.persistence.IEntityManager;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.poll.IPollable;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.storage.IStorageFactory;
import com.alfaariss.oa.engine.core.session.SessionException;

/**
 * An interface for session factories.
 *
 * Implementations of this interface can be used to generate and store sessions. 
 * These factories should be implemented using the abstract factory design 
 * pattern. 
 * 
 * @author EVB
 * @author Alfa & Ariss
 * @param <E> The type of session. 
 *
 */
public interface ISessionFactory<E extends ISession> 
    extends IEntityManager<E>, IStorageFactory, IPollable, IAuthority
{
    /** The authority name of Session Factory implementations. */
    public static final String AUTHORITY_NAME = "SessionFactory";
    
    /**
     * Create a new empty session.
     * @param sRequestorId The id of the requestor.
     * @return ISession The new session.
     * @throws SessionException If creation fails.
     */
    public ISession createSession(String sRequestorId) throws SessionException;
    
    /**
     * Retrieve a session.
     * @see IEntityManager#retrieve(java.lang.Object)
     */
    public E retrieve(Object id) throws PersistenceException;
}
