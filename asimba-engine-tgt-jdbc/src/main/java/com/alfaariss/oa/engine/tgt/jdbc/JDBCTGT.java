/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.engine.tgt.jdbc;
import java.util.List;

import com.alfaariss.oa.api.persistence.IEntity;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.tgt.TGTListenerEvent;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.attribute.TGTAttributes;
import com.alfaariss.oa.engine.core.tgt.AbstractTGT;

/**
 * An TGT implementation which can be added to a JDBC storage.
 *
 * Uses the OA persistence API.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class JDBCTGT extends AbstractTGT 
{   
	//The persistance context    
    private transient JDBCTGTFactory _context;   
      
    /**
     * Create a new empty <code>JDBCTGT</code>.
     * @param context JDBC factory 
     * @param user User ID
     */
    public JDBCTGT(JDBCTGTFactory context, IUser user)
    {
        super(user);
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
    
    /**
     * Sets the Requestor ID list 
     * @param listRequestorIDs
     * @since 1.0
     */
    void setRequestorIDs(List<String> listRequestorIDs)
    {
        _listRequestorIDs = listRequestorIDs;
    }
    
    List<String> getModifiableRequestorIDs()
    {
        return _listRequestorIDs;
    }
    
    List<String> getModifiableAuthNProfileIDs()
    {
        return _authNProfileIDs;
    }
    
    /**
     * Set a new set of attributes.
     * @param expirationTime The new expiration time.
     */
    void setAttributes(TGTAttributes attributes)
    {
        _attributes = attributes;
    }
}