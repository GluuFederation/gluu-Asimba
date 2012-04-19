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
package com.alfaariss.oa.api.tgt;
import java.util.Date;
import java.util.List;

import com.alfaariss.oa.api.attribute.ITGTAttributes;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.persistence.IEntity;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.user.IUser;

/**
 * An interface for TGTs.
 *
 * Describes a common interface for <b>T</b>icket <b>G</b>ranting <b>T</b>ickets.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public interface ITGT extends IEntity 
{   
    /**
     * Size of a TGT
     */
    public final static int TGT_LENGTH = 128; 
           
    /**
     * Retrieve the TGT id.
     * @return The id of this TGT.
     */
    public String getId(); 

	/**
     * Retrieve all authentication methods this TGT contains.
     * 
	 * Retrieve all authentication methods which are succesfully performed 
     * during this TGT in a single profile.
	 * @return All authentication methods this TGT contains.
	 */
	public IAuthenticationProfile getAuthenticationProfile();

	/**
	 * Add an authentication profile to this TGT.
	 *
	 * Should be used whenever the owner of this TGT succesfully authenticates 
     * using the given authentication profile.  
	 * @param profile The authentication profile to be added.
	 */
	public void setAuthenticationProfile(IAuthenticationProfile profile);
    
    /**
     * Check if this TGT is expired.
     * @return <code>true</code> if this session is expired.
     */
    public boolean isExpired();

	/**
	 * Retrieve the expiretime of this TGT.
	 * @return The TGT expiration time.
	 */
	public Date getTgtExpTime();
    
    /**
     * Expire this tgt.
     */
    public void expire();

	/**
	 * Retrieve the owner of this TGT.
	 * @return IUser The owner of this TGT.
	 */
	public IUser getUser();

	/**
	 * Set a new owner for this TGT.
	 * @param user The new owner of this TGT.
	 */
	public void setUser(IUser user);    
    
    /**
     * Returns all previously performed authentication profile ID's.
     * @return A list with authentication profiles
     */
    public List<String> getAuthNProfileIDs();

    /**
     * Add a performed authentication profile.
     * @param sProfileID A performed authentication profile id
     */
    public void addAuthNProfileID(String sProfileID);
    
    /**
     * Returns all requestor ID's where is user is authenticated for.
     *
     * @return List<String> containing all requestor ID's.
     * @since 1.0
     */
    public List<String> getRequestorIDs();
    
    /**
     * Add a unique requestor ID where the user is authenticated for. 
     * @param sRequestorID
     * @since 1.0
     */
    public void addRequestorID(String sRequestorID);
    
    /**
     * Remove a requestor ID where the user is authenticated for. 
     * @param sRequestorID
     * @return TRUE if the requestor id is removed
     * @since 1.4
     */
    public boolean removeRequestorID(String sRequestorID);
    
    /**
     * Retrieve the TGT scope attributes.
     * @return The attributes contained in the session.
     */
    public ITGTAttributes getAttributes();
    
    /**
     * Performs a persist, but without performing the corresponding TGT 
     * listener event.
     * @see IEntity#persist()
     * 
     * @return The <code>TGTListenerEvent</code> that has been passed.
     * @throws PersistenceException If persistance fails.
     * @since 1.4
     */
    public TGTListenerEvent persistPassingListenerEvent()
      throws PersistenceException;
    
    /**
     * Cleans the TGT.
     * @see IEntity#persist()
     * 
     * @throws PersistenceException If cleaning fails.
     * @since 1.4
     */
    public void clean() throws PersistenceException;
}