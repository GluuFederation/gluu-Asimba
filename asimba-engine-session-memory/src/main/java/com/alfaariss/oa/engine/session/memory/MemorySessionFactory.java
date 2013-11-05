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
package com.alfaariss.oa.engine.session.memory;

import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.persistence.IEntity;
import com.alfaariss.oa.api.persistence.IEntityManager;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.storage.IStorageFactory;
import com.alfaariss.oa.api.storage.clean.ICleanable;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.session.SessionException;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;
import com.alfaariss.oa.util.ModifiedBase64;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.storage.factory.AbstractStorageFactory;
/**
 * Simple {@link ISessionFactory} which stores sessions in a {@link Hashtable}.
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class MemorySessionFactory extends AbstractStorageFactory 
    implements ISessionFactory<MemorySession>
{    
    private Hashtable<String, MemorySession> _htSession; 
    //The system logger
    private Log _logger;
    private Log _eventLogger;
       
    /**
     * Create a new <code>MemoryFactory</code>.
     */
    public MemorySessionFactory()
    {
        super();
        _logger = LogFactory.getLog(MemorySessionFactory.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
        _htSession = new Hashtable<String, MemorySession>(); 
    }

    /**
     * Create a new <code>MemorySession</code>.
     * @see com.alfaariss.oa.engine.core.session.factory.ISessionFactory#createSession(java.lang.String)
     */
    public ISession createSession(String sRequestorId) throws SessionException
    {
        if(sRequestorId == null)
            throw new IllegalArgumentException("Suplied requestor id is empty");  
        if(_lMax > 0 && _htSession.size() >= _lMax)
        {
            _logger.error("Could not create session, maximum reached");
            throw new SessionException(SystemErrors.ERROR_SESSION_MAX);
        }
        return new MemorySession(this, sRequestorId);
     }

    /**
     * Check if a session with the given id exists.
     * @see IEntityManager#exists(java.lang.Object)
     */
    public boolean exists(Object id)
    {
        return _htSession.containsKey(id);
    }

    /**
     * Restore an existing session from the storage.
     * @see IEntityManager#retrieve(java.lang.Object)
     */
    public MemorySession retrieve(Object id) throws PersistenceException
    {
        if (_logger.isDebugEnabled())
            _logger.debug("Current sessions: " + _htSession);
        
        return _htSession.get(id);
    }

    /**
     * Persist this session in an <code>Hashtable</code>.
     * 
     * <dl>
     *  <dt><code>id == null</code></dt>
     *  <dd>Generate new unique and random id and store session</dd>
     *  <dt><code>expiration time <= current time</code></dt>
     *  <dd>Remove session from storage</dd>
     * </dl>
     * @param session the session to persist. 
     * @throws PersistenceException If perstistance fails.
     * 
     * @see IEntityManager#persist(IEntity)
     */
    public synchronized void persist(MemorySession session) 
        throws PersistenceException
    {
        String id = session.getId();
        if(id == null) //New session
        {
            byte[] baId = new byte[ISession.ID_BYTE_LENGTH];    
            do
            {                
                _random.nextBytes(baId);
                try
                {
                    id = ModifiedBase64.encode(baId);
                }
                catch (UnsupportedEncodingException e)
                {
                    _logger.error("Could not create id for byte[]: " + baId, e);
                    throw new PersistenceException(SystemErrors.ERROR_INTERNAL);
                }
            }
            while(_htSession.containsKey(id)); //Key allready exists    
            
            session.setId(id);
            //Update expiration time
            session.setExpTime(System.currentTimeMillis() + _lExpiration);
            _htSession.put(id, session);
            
            _logger.info("New session(s) added: " + id + " for requestor '"+session.getRequestorId() + "'");
        }
        else if(session.isExpired()) //Expired
        {
            _logger.info("Session Expired: " + id);  
            
            _eventLogger.info(new UserEventLogItem(session, null, 
                UserEvent.SESSION_EXPIRED, this, null));
            
            _htSession.remove(id);
        }    
        else //Update
        {
            //Update expiration time
            session.setExpTime(System.currentTimeMillis() + _lExpiration);
            //Storing can be omitted when using a Hashtable
            _logger.info("Existing session(s) updated: " + id + " for requestor '"+session.getRequestorId() + "'");
        }
    }

    /**
     * Persist all sessions in an <code>Hashtable</code>.
     * @param oaSession The sessions to persist.
     * @throws PersistenceException If persistance fails.
     * @see IEntityManager#persist(IEntity[])
     * @see MemorySessionFactory#persist(MemorySession)
     */
    public void persist(MemorySession[] oaSession) throws PersistenceException
    {
        for(MemorySession session : oaSession)
            persist(session);
    }

    /**
     * Remove all expired sessions.
     * @see ICleanable#removeExpired()
     */
    public void removeExpired() throws PersistenceException
    {
        long lNow = System.currentTimeMillis();
        Enumeration<MemorySession> e = _htSession.elements();
        while(e.hasMoreElements()) //Threadsafe iteration
        {          
            MemorySession session = e.nextElement(); 
            if(session.getExpTime() <= lNow)
            {
                String id = session.getId();             
                _logger.info("Session Expired: " + id);
                
                _eventLogger.info(new UserEventLogItem(session, null, 
                    UserEvent.SESSION_EXPIRED, this, "clean"));
                
                _htSession.remove(id);
            }
        }        
    }

    /**
     * Start cleaner
     * @see IStorageFactory#start()
     */
    public void start() throws OAException
    {
        if(_tCleaner != null)
            _tCleaner.start();     
    }

    /**
     * @see com.alfaariss.oa.api.poll.IPollable#poll()
     */
    public long poll() throws OAException
    {
        if (_htSession!=null) 
        {
            return _htSession.size();
        }
        return Long.MIN_VALUE;
    }
    
    /**
     * @see com.alfaariss.oa.api.logging.IAuthority#getAuthority()
     * @since 1.3
     */
    public String getAuthority()
    {
        return ISessionFactory.AUTHORITY_NAME;
    }
}
