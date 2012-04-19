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
package com.alfaariss.oa.engine.core.user;

import java.util.Enumeration;

import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.attribute.UserAttributes;

/**
 * Creates a user and contains the equal and hashcode methods.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
abstract public class AbstractUser implements IUser
{
    /** The required user id */
    private String _sUserId;
    /** The required user organization id */
    private String _sOrganization;
    private boolean _bEnabled;
    private UserAttributes _attributes;
    
    /**
     * Creates the user.
     * @param sOrganization The organization of the user
     * @param sUserId The unique user id within the organization
     * @param bEnabled TRUE if account is enabled
     */
    protected AbstractUser(String sOrganization, String sUserId, boolean bEnabled)
    {
        _sUserId = sUserId;
        _sOrganization = sOrganization;
        _bEnabled = bEnabled;
        _attributes = new UserAttributes();
    }
    
    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        StringBuffer sbThisUser = new StringBuffer();
        sbThisUser.append(_sUserId);
        sbThisUser.append("@");
        sbThisUser.append(_sOrganization);
        
        return sbThisUser.toString().hashCode();
    }
    
    /**
     * Returns TRUE if id and organization of both users are equally.
     * The user id is compared case insensitive and the organization is 
     * compared case sensitive.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object other)
    {
        if(!(other instanceof IUser))
            return false; 
        
        IUser oUser = (IUser)other;
        
        String sOtherUserID = oUser.getID();
        if (sOtherUserID == null)
        {
            if (this.getID() != null)
                return false;
        }
        else if (!sOtherUserID.equalsIgnoreCase(this.getID()))
            return false;
            
        String sOtherOrganization = oUser.getOrganization();    
        if (sOtherOrganization == null)
        {
            if (this.getOrganization() != null)
                return false;
        }
        else if (!sOtherOrganization.equals(this.getOrganization()))
            return false;
        
        return true;
    }
    
    /**
     * @see com.alfaariss.oa.api.user.IUser#getOrganization()
     */
    public String getOrganization()
    {
        return _sOrganization;
    }

    /**
     * The user id.
     * @see com.alfaariss.oa.api.user.IUser#getID()
     */
    public String getID()
    {
        return _sUserId;
    }
    
    /**
     * Returns TRUE if the account is enabled.
     * @see com.alfaariss.oa.api.user.IUser#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
    
    /**
     * Returns the specific user attributes.
     * @see com.alfaariss.oa.api.user.IUser#getAttributes()
     */
    public IAttributes getAttributes()
    {
        return _attributes;
    }
    
    /**
     * Updates the supplied attributes object with the user attributes.
     * @see com.alfaariss.oa.api.user.IUser#setAttributes(com.alfaariss.oa.api.attribute.IAttributes)
     */
    public void setAttributes(IAttributes oAttributes)
    {
        Enumeration enumNames = oAttributes.getNames();
        while (enumNames.hasMoreElements())
        {
            String sName = (String)enumNames.nextElement();
            _attributes.put(sName, oAttributes.getFormat(sName), 
                oAttributes.get(sName));
        }
    }
}
