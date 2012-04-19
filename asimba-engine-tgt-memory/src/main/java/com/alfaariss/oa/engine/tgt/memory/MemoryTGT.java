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
package com.alfaariss.oa.engine.tgt.memory;
import com.alfaariss.oa.api.persistence.IEntity;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.tgt.TGTListenerEvent;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.tgt.AbstractTGT;

/**
 * A simple TGT implementation which can be stored in memory.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class MemoryTGT extends AbstractTGT 
{
    //The persistance context
    private transient MemoryTGTFactory _context;   

	/**
	 * Create a new <code>AbstractTGT</code>.
	 * @param context The context of this TGT. 
	 * @param user The owner for this TGT.
	 */
	public MemoryTGT(MemoryTGTFactory context, IUser user)
    {
        super(user);
	    _context = context;
	} 
    
	/**
     * Persist this TGT in the context.
	 * @see IEntity#persist()
	 */
	public void persist()
	  throws PersistenceException
    {   
	    _context.persist(this);
	}
	
    /**
     * @see com.alfaariss.oa.api.tgt.ITGT#persistPassingListenerEvent()
     */
    public TGTListenerEvent persistPassingListenerEvent()
        throws PersistenceException
    {
        return _context.persistPassingListenerEvent(this);
    }
    
    /**
     * @see com.alfaariss.oa.api.tgt.ITGT#clean()
     */
    public void clean() throws PersistenceException
    {
        _context.clean(this);
    }
    
    /**
     * Set a new TGT id.
     * @param id The new id.
     */
    void setId(String id)
    {
        _id = id;
    }
    
    /**
     * Set a new TGT expiration time.
     * @param expirationTime The new TGT expiration time.
     */
    void setTgtExpTime(long expirationTime)
    {
        _lExpireTime = expirationTime;   
    }
}