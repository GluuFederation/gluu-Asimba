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
package com.alfaariss.oa.engine.core.requestor;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;

import com.alfaariss.oa.api.IManagebleItem;
import com.alfaariss.oa.api.requestor.IRequestor;

/**
 * A default pool containing requestors.
 * One pool can only contain one type of requestor.
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class RequestorPool implements IManagebleItem 
{
    /** pool id */
    protected String _sID;
    /** friendly name */
    protected String _sFriendlyName;
    /** enabled */
    protected boolean _bEnabled;
    /** forced */
    protected boolean _bForced;
    /** pre authorization profile id */
    protected String _sPreAuthorizationProfileID;
    /** post authorization profile id */
    protected String _sPostAuthorizationProfileID;
    /** attribute release policy id */
    protected String _sAttributeReleasePolicyID; 
    /** properties */
    protected Properties _properties;
    
    private List<String> _listAuthenticationProfileIDs;
    private Set<IRequestor> _setRequestors;
    
    /**
     * Create a new requestor pool.
     * @param id the unique id of the pool
     * @param friendlyName the readable name of the pool
     * @param enabled TRUE if this object is enabled
     * @param enableForcedAuthentication TRUE if forced authentication is enabled
     * @param sPreAuthorizationProfileID the ID of the pre authorization profile for this pool
     * @param sPostAuthorizationProfileID the ID of the post authorization profile for this pool 
     * @param sAttributeReleasePolicyID the ID of the attribute release policy
     * @param requestors a set of requestor objects
     * @param authenticationProfileIDs a sequence of authentication profiles
     */
    public RequestorPool(String id, String friendlyName, boolean enabled,
        boolean enableForcedAuthentication, String sPreAuthorizationProfileID,
        String sPostAuthorizationProfileID, String sAttributeReleasePolicyID,
        Set<IRequestor> requestors, List<String> authenticationProfileIDs)
    {
        _sID = id;
        _sFriendlyName = friendlyName;
        _bEnabled = enabled;
        _bForced = enableForcedAuthentication;
        _sPreAuthorizationProfileID = sPreAuthorizationProfileID;
        _sPostAuthorizationProfileID = sPostAuthorizationProfileID;
        _sAttributeReleasePolicyID = sAttributeReleasePolicyID;
        _setRequestors = requestors;
        _listAuthenticationProfileIDs = authenticationProfileIDs;
        _properties = new Properties();
    }

    /**
     * The unique ID.
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    public String getID()
    {
        return _sID;
    }
    
    /**
     * The readable friendly name.
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }
    
    /**
     * Returns TRUE if this object is enabled.
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }

    /**
     * Is forced authenticate enabled?
     * @return <code>true</code> if forced authenticate is enabled.
     */
    public boolean isForcedAuthenticate()
    {
        return _bForced;
    }
    
    /**
     * Verifies if the requestor ID is part of this requestor pool.
     * @param sRequestor The requestor ID
     * @return TRUE if the requestor is part of the pool
     */
    public boolean existRequestor(String sRequestor)
    {
        for (IRequestor oRequestor: _setRequestors)
        {
            if (oRequestor.getID().equals(sRequestor))
                return true;
        }
        return false;
    }
    
    /**
     * Retrieve the required authentication profiles.
     * @return A sequence of ID's of the required authentication profiles.
     */
    public List<String> getAuthenticationProfileIDs()
    {
        return _listAuthenticationProfileIDs;
    }

    /**
     * Retrieve the required PreAuthorization profile.
     * @return The ID of the required PreAuthorization profile.
     */
    public String getPreAuthorizationProfileID()
    {
        return _sPreAuthorizationProfileID;
    }

    /**
     * Retrieve the required PostAuthorization profile.
     * @return The ID of the required PostAuthorization profile.
     */
    public String getPostAuthorizationProfileID()
    {
        return _sPostAuthorizationProfileID;
    }

    /**
     * Retrieve the AttributeRelease profile.
     * @return The ID of the AttributeRelease profile.
     */
    public String getAttributeReleasePolicyID()
    {
           return _sAttributeReleasePolicyID;
    }
    
    /**
     * Returns the list of all requestors in this pool.
     * @return the list with requestors.
     */
    public Set<IRequestor> getRequestors()
    {
        return _setRequestors;
    }
    
    /**
     * The {@link java.lang.Object#hashCode()} of the ID.
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        return _sID.hashCode();
    }
    
    /**
     * Returns <code>ID.equals(other.ID)</code>.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object other)
    {
        if(!(other instanceof RequestorPool))
            return false;        
        return _sID.equals(((RequestorPool)other)._sID);
    }
    
    /**
     * Retrieve the extended properties of this requestorpool.
     * This collection should be properted by means of 
     * {@link Collections#unmodifiableMap(Map)}.
     * 
     * @return Map The requestorpool properties.
     */
    public Map getProperties()
    {
        return Collections.unmodifiableMap(_properties);
    }

    /**
     * Retrieve a single extended property value of this requestorpool.
     * @param name The property name.
     * @return Object The requestorpool property value.
     */
    public Object getProperty(String name)
    {
        return _properties.get(name);
    }

    /**
     * Check if a single extended property exists for this requestorpool.
     * @param name The property name.
     * @return <code>true</code> if the property exists.
     */
    public boolean isProperty(String name)
    {
        return _properties.containsKey(name);
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

    /**
     * Creates the pool object without setting any class variables.
     */
    protected RequestorPool()
    {
        _sID = null;
        _sFriendlyName = null;
        _bEnabled = false;
        _setRequestors = new HashSet<IRequestor>();
        _listAuthenticationProfileIDs = new Vector<String>();
    }

    /**
     * Adds an authentication profile to the requestor pool.
     * @param sAuthenticationProfileID The authentication id that must be added 
     * at the end of the sequence.
     */
    protected void addAuthenticationProfileID(String sAuthenticationProfileID)
    {
        _listAuthenticationProfileIDs.add(sAuthenticationProfileID);
    }

    /**
     * Add an requestor.
     * @param requestor The requestor that must be added
     */
    protected void addRequestor(IRequestor requestor)
    {
        _setRequestors.add(requestor);
    }
}