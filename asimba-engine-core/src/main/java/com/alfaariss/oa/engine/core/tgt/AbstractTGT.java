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
package com.alfaariss.oa.engine.core.tgt;
import java.io.Serializable;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import com.alfaariss.oa.api.attribute.ITGTAttributes;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.attribute.TGTAttributes;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;

/**
 * A base TGT (ticket-granting ticket) implementation.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public abstract class AbstractTGT implements ITGT, Serializable 
{ 
	private static final long serialVersionUID = 1998890823651449352L;
	/** tgt id */
    protected String _id;
    /** expire time */
    protected long _lExpireTime;
    /** requestor list */
    protected List<String> _listRequestorIDs;
    /** modifiable authn profile list */ 
    protected List<String> _authNProfileIDs;
    /** TGT attributes */
    protected ITGTAttributes _attributes;
    
    private IUser _uOwner;
    private IAuthenticationProfile _authNProfile;
    
	/**
	 * Create a new <code>AbstractTGT</code>.
	 * @param user The owner for this TGT.
	 */
	public AbstractTGT(IUser user)
    {
        _uOwner = user;
        _authNProfile = new AuthenticationProfile(
            "tgt", "TGT Profile", true);
        _authNProfileIDs = new Vector<String>();
        _listRequestorIDs = new Vector<String>();
        _attributes = new TGTAttributes();
	} 

    /**
	 * @see com.alfaariss.oa.api.tgt.ITGT#getId()
	 */
	public String getId()
    {
        return _id;
    }

    /**
     * @see ITGT#getAuthenticationProfile()
     */
    public IAuthenticationProfile getAuthenticationProfile()
    {
    	return _authNProfile;
    }

    /**
     * @see com.alfaariss.oa.api.tgt.ITGT#setAuthenticationProfile(
     *  IAuthenticationProfile)
     */
    public void setAuthenticationProfile(IAuthenticationProfile profile)
    {
        _authNProfile = profile;
    }
    
    /**
     * @see com.alfaariss.oa.api.tgt.ITGT#addAuthNProfileID(java.lang.String)
     */
    public void addAuthNProfileID(String sProfileID)
    {
        _authNProfileIDs.add(sProfileID);        
    }
    
    /**
     * @param authNProfileIDs The updated authnProfileIDs.
     */
    public void setAuthNProfileIDs(List<String> authNProfileIDs)
    {
        _authNProfileIDs = authNProfileIDs;
    }

    /**
     * @see com.alfaariss.oa.api.tgt.ITGT#getAuthNProfileIDs()
     */
    public List<String> getAuthNProfileIDs()
    {
        return Collections.unmodifiableList(_authNProfileIDs);
    }

	/**
	 * @see com.alfaariss.oa.api.tgt.ITGT#setUser(com.alfaariss.oa.api.user.IUser)
	 */
	public void setUser(IUser user)
    {
        _uOwner = user;
	}

	/**
	 * @see com.alfaariss.oa.api.tgt.ITGT#getUser()
	 */
	public IUser getUser()
    {
    	return _uOwner;
    }
    
    /**
     * @see com.alfaariss.oa.api.tgt.ITGT#isExpired()
     */
    public boolean isExpired()
    {
        return _lExpireTime <= System.currentTimeMillis();
    }

    /**
     * @see com.alfaariss.oa.api.tgt.ITGT#getTgtExpTime()
     */
    public Date getTgtExpTime()
    {
		return new Date(_lExpireTime);
	}
    
    /**
     * @see com.alfaariss.oa.api.tgt.ITGT#expire()
     */
    public void expire()
    {
        _lExpireTime = 0;
        
    }
  
    /**
     * Return the hashcode from the id.
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        return _id.hashCode();
    }
    
    /**
     * Compare ID.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object other)
    {
        if(!(other instanceof AbstractTGT))
            return false;        
        return _id.equals(((AbstractTGT)other)._id);
    }
    
    /**
     * @see com.alfaariss.oa.api.tgt.ITGT#addRequestorID(java.lang.String)
     */
    public void addRequestorID(String sRequestorID)
    {
        _listRequestorIDs.add(sRequestorID);
    }

    /**
     * @see com.alfaariss.oa.api.tgt.ITGT#removeRequestorID(java.lang.String)
     */
    public boolean removeRequestorID(String sRequestorID)
    {
        return _listRequestorIDs.remove(sRequestorID);
    }

    /**
     * Returns an unmodifiable list of strings.
     * @see com.alfaariss.oa.api.tgt.ITGT#getRequestorIDs()
     */
    public List<String> getRequestorIDs()
    {
        return Collections.unmodifiableList(_listRequestorIDs);
    }
    
    /**
     * @see com.alfaariss.oa.api.tgt.ITGT#getAttributes()
     */
    public ITGTAttributes getAttributes()
    {
        return _attributes;
    }
}