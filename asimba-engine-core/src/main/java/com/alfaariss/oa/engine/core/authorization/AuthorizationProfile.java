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
package com.alfaariss.oa.engine.core.authorization;
import java.util.List;
import java.util.Vector;

import com.alfaariss.oa.api.IManagebleItem;


/**
 * Simple Bean implementation of the authorization profile.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class AuthorizationProfile implements IManagebleItem 
{
    /** profile id */
    protected String _sID;
    /** friendly name */
    protected String _sFriendlyName;
    /** enabled */
    protected boolean _bEnabled;
    /** authorization method list */
    protected List<AuthorizationMethod> _listAuthorizationMethod;
    
    /**
     * Creates the profile object with empty items.
     *
     * If this constructor is used, the protected class variables should be set 
     * manualy.
     */
    protected AuthorizationProfile()
    {
        _sID = null;
        _sFriendlyName = null;
        _bEnabled = false;
    }
    
    /**
     * Creates an instance of the authorization profile object.
     * 
     * The supplied <code>sId</code> and <code>sFriendlyName</code> may not be 
     * <code>null</code>.
     * 
     * @param sID the ID of the authorization profile
     * @param sFriendlyName the friendly name of the authorization profile
     * @param bEnabled TRUE if the authorization profile is enabled
     */
    public AuthorizationProfile(String sID, String sFriendlyName
        , boolean bEnabled)
    {
        _sID = sID;
        _sFriendlyName = sFriendlyName;
        _bEnabled = bEnabled;
        _listAuthorizationMethod = new Vector<AuthorizationMethod>();
    }


    /**
     * Returns the profile id.
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    public String getID()
    {
        return _sID;
    }

    /**
     * Returns the profile displayable friendly name.
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }
    
    /**
     * Returns TRUE if this profile is enabled.
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
    
    /**
     * Adds an authorization method at the end of the sequence. 
     * @param oAuthorizationMethod the authorization method to add
     */
    public void addAuthorizationMethod(AuthorizationMethod oAuthorizationMethod)
    {
        _listAuthorizationMethod.add(oAuthorizationMethod);
    }
    
    /**
     * Returns the sequence with authorization method objects defined in this profile.
     * @return a list with authorization method objects
     */
    public List<AuthorizationMethod> getAuthorizationMethods()
    {
        return _listAuthorizationMethod;
    }
    
    /**
     * Returns the hashcode based on the profile id.
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        return _sID.hashCode();        
    }
    
    /**
     * Verifies wheter the supplied profile is equal to this profile.
     * 
     * @return <code>true</code> if this id is equal to the other profile id.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object obj)
    {
        if (!(obj instanceof AuthorizationProfile))
            return false;        
        AuthorizationProfile oAuthorizationProfile = (AuthorizationProfile)obj;
        
        return _sID.equals(oAuthorizationProfile._sID);
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer sbInfo = new StringBuffer(_sFriendlyName);
        sbInfo.append(" (").append(_sID).append(")");
        return sbInfo.toString();
    }

}