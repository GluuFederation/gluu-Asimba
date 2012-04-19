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
package com.alfaariss.oa.engine.core.authentication;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;

import com.alfaariss.oa.api.authentication.IAuthenticationMethod;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;

/**
 * Simple bean implementation of the authentication profile. 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class AuthenticationProfile implements IAuthenticationProfile, Serializable 
{
    /** profile id */
    protected String _sID;
    /** friendly name */
    protected String _sFriendlyName;
    /** enabled */
    protected boolean _bEnabled; 
    /** authentication method list */
    protected List<IAuthenticationMethod> _listAuthenticationMethods;
    /** properties */
    protected Properties _properties;
    /** serialVersionUID */
    private static final long serialVersionUID = 7667587169082046403L;
    
    /**
     * Creates the profile object with empty items.
     *
     * If this constructor is used, the protected class variables should be set 
     * manualy.
     */
    protected AuthenticationProfile()
    {
        _sID = null;
        _sFriendlyName = null;
        _bEnabled = false;
        _listAuthenticationMethods = new Vector<IAuthenticationMethod>();
        _properties = new Properties();
    }
    
	/**
     * Creates the profile object.
     * 
     * The supplied <code>sId</code> and <code>sFriendlyName</code> may not be 
     * <code>null</code>.
     * 
	 * @param sID the ID of the authentication method
     * @param sFriendlyName the friendly name of the authentication method
     * @param bEnabled TRUE if the authentication method is enabled
	 */
	public AuthenticationProfile(String sID, String sFriendlyName
        , boolean bEnabled)
    {
        _sID = sID;
        _sFriendlyName = sFriendlyName;
        _bEnabled = bEnabled;        
        _listAuthenticationMethods = new Vector<IAuthenticationMethod>();
        _properties = new Properties();
	}

    /**
     * The unique ID of this profile.
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    public String getID()
    {
        return _sID;
    }
    
    /**
     * The name of the profile that can be displayed.
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

    /**
     * Returns TRUE if this profile is enabled
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
    
    /**
     * Add an authentication method at the end of the list.
     * @param oAuthenticationMethod The method that must be added
     */
    public void addAuthenticationMethod(IAuthenticationMethod oAuthenticationMethod)
    {
        _listAuthenticationMethods.add(oAuthenticationMethod);
    }
    
	/**
     * Returns the list of authentication methods.
	 * @return the list with authentication methods
	 */
	public List<IAuthenticationMethod> getAuthenticationMethods()
    {
		return _listAuthenticationMethods;
	}
	
	/**
	 * Check if the current authentication profile contains the given method.
	 * @see IAuthenticationProfile#containsMethod(IAuthenticationMethod)
	 */
	public boolean containsMethod(IAuthenticationMethod method)
    {
        return _listAuthenticationMethods.contains(method);
    }

	/**
	 * Compares this profile with the given profile.
	 *
     * <ul>
     * <li>Returns -1 if the supplied profile does not contain a subset of 
     * methods that this profile contains (not sufficient)</li>
     * <li>Returns 0 if this profile contains all methods that the supplied 
     * profile contains (sufficient).</li>
     * <li>Returns 1 if the supplied profile contains a subset of methods that 
     * profile contains (sufficient).</li>
     * </ul>
     * 
	 * @param profile An AuthenticationProfile object
	 * @return -1, 0 or 1
	 */
	public int compareTo(IAuthenticationProfile profile)
    {
         List<IAuthenticationMethod> setAuthenticationMethods =
             profile.getAuthenticationMethods();
        if (_listAuthenticationMethods.containsAll(setAuthenticationMethods))
            return 0;
        
        for(IAuthenticationMethod oAuthenticationMethod: setAuthenticationMethods)
        {
            if (!_listAuthenticationMethods.contains(oAuthenticationMethod))
                return -1;
        }
        
        return 1;
	}
	
    /**
     * Retrieve the extended properties of this authentication profile.
     * This collection should be properted by means of 
     * {@link Collections#unmodifiableMap(Map)}.
     * 
     * @return Map The authentication profile properties.
     */
    public Map getProperties()
    {
        return Collections.unmodifiableMap(_properties);
    }

    /**
     * Retrieve a single extended property value of this authentication profile.
     * @param name The property name.
     * @return Object The authentication profile property value.
     */
    public Object getProperty(String name)
    {
        return _properties.get(name);
    }

    /**
     * Check if a single extended property exists for this authentication profile.
     * @param name The property name.
     * @return <code>true</code> if the property exists.
     */
    public boolean isProperty(String name)
    {
        return _properties.containsKey(name);
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
     * Verifies whether the supplied authentication profile is equal to this profile.
     * 
     * Returns TRUE if the ID of the supplied authentication profile ID is 
     * equal to the ID of this profile. 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object obj)
    {
        if (!(obj instanceof AuthenticationProfile))
            return false;
        
        AuthenticationProfile oAuthenticationProfile = (AuthenticationProfile)obj;
        
        return _sID.equals(oAuthenticationProfile._sID);
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