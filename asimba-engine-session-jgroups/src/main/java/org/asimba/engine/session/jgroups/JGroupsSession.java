/*
 * Asimba Server
 * 
 * Copyright (C) 2015 Asimba
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
package org.asimba.engine.session.jgroups;

import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.engine.core.session.AbstractSession;

public class JGroupsSession extends AbstractSession {

	private transient JGroupsSessionFactory _oSessionFactory;
	
	
	/**
     * Create a new <code>MemorySession</code>.
     * @param context The context of this Session. 
     * @param requestorId The id of the requestor for which this authentication
     *  session is created. 
     */
    public JGroupsSession(JGroupsSessionFactory oSessionFactory, String requestorId)
    {
        super(requestorId);
        _oSessionFactory = oSessionFactory;
    } 
    
	
	@Override
	public void persist() throws PersistenceException 
	{
		_oSessionFactory.persist(this);
	}

	
    private void setSessionFactory(JGroupsSessionFactory oSessionFactory)
    {
    	_oSessionFactory = oSessionFactory;
    }

    
	/**
	 * Note: this method must be called after deserializing a JGroupsSession to re-set the 
	 * ISessionFactory that can persist the Session
	 * 
	 * @param oSessionFactory
	 * @return
	 */
	public void resuscitate(JGroupsSessionFactory oSessionFactory)
	{
		setSessionFactory(oSessionFactory);
	}

	
    /**
     * Set a new Session ID.
     * @param id The new session ID.
     */
    void setId(String id)
    {
        _id = id;        
    }

}
