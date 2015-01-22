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
package org.asimba.engine.tgt.jgroups;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.tgt.TGTListenerEvent;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.tgt.AbstractTGT;

public class JGroupsTGT extends AbstractTGT implements Serializable {

	//The persistence context
	private transient JGroupsTGTFactory _oTGTFactory;

	private List<String> _lAliasList;


	public JGroupsTGT(JGroupsTGTFactory oTGTFactory, IUser oUser)
	{
		super(oUser);
		_oTGTFactory = oTGTFactory;
		
		_lAliasList = new ArrayList<>();
	}
	
	
	/**
	 * This is private so the createJGroupsTGT() method can access it, but others can not.
	 * @param oTGTFactory
	 */
	private void setTGTFactory(JGroupsTGTFactory oTGTFactory)
	{
		_oTGTFactory = oTGTFactory;
	}

	
	/**
	 * Note: this method must be called after deserializing a JGroupsTGT to re-set the ITGTFactory that
	 * can persist the TGT.
	 * 
	 * @param oTGTFactory
	 * @return
	 */
	public void resuscitate(JGroupsTGTFactory oTGTFactory)
	{
		setTGTFactory(oTGTFactory);
	}
	
	
	@Override
	public TGTListenerEvent persistPassingListenerEvent() throws PersistenceException 
	{
		return _oTGTFactory.persistPassingListenerEvent(this);
	}

	
    /**
     * Set a new TGT id.<br/>
     * <br/>
     * Note: default package private visibility, so JGroupsTGTFactory<br/> 
     * can set the Id but others can not.
     * 
     * @param id The new id.
     */
    void setId(String id)
    {
        _id = id;
    }

    
    /**
     * Set a new TGT expiration time.<br/>
     * <br/>
     * Note: default package private visibility, so JGroupsTGTFactory<br/> 
     * can set the expirationTime but others can not.
     * 
     * @param expirationTime The new TGT expiration time.
     */
    void setTgtExpTime(long expirationTime)
    {
        _lExpireTime = expirationTime;   
    }
    
    
	@Override
	public void clean() throws PersistenceException {
		_oTGTFactory.clean(this);
	}

	
	@Override
	public void persist() throws PersistenceException {
		_oTGTFactory.persist(this);
	}

	
	/**
	 * Add a new alias with the local JGroups TGT registration
	 * @param sKey
	 */
	public void registerAlias(String sKey) {
		_lAliasList.add(sKey);
	}
	
	
	/**
	 * Retrieve all the aliases that are registered with this TGT
	 * @return
	 */
	public List<String> getAliases() {
		return _lAliasList;
	}


}
