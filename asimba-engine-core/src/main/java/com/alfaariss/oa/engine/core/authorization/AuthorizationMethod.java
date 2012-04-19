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

import java.io.Serializable;


/**
 * Simple Bean implementation of the authorization method.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class AuthorizationMethod implements Serializable
{
    private static final long serialVersionUID = 6781066630164141295L;

    /** method id */
    protected String _sID;
    
    /**
     * Creates the method object with empty items.
     *
     * If this constructor is used, the protected class variables should be set 
     * manually.
     */
    protected AuthorizationMethod()
    {
        _sID = null;
    }
    
    /**
     * Creates an instance of the authorization method object.
     * 
     * The supplied <code>sId</code> may not be <code>null</code>.
     * 
     * @param sID the ID of the authorization method
     */
    public AuthorizationMethod(String sID)
    {
        _sID = sID;
    }

    /**
     * Returns the method id.
     * @return The id
     */
    public String getID()
    {
        return _sID;
    }
    
    /**
     * Returns the hashcode based on the authorization method id.
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        return _sID.hashCode();        
    }
    
    /**
     * Returns <code>true</code> if the ID of the supplied authorization method 
     * ID is equal to the ID of this authorization method. 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object obj)
    {
        if (!(obj instanceof AuthorizationMethod))
            return false;
        
        AuthorizationMethod oAuthorizationMethod = (AuthorizationMethod)obj;
        
        return _sID.equals(oAuthorizationMethod._sID);
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        return "Authorization method: " + _sID;
    }
}