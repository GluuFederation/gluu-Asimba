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

import com.alfaariss.oa.api.authentication.IAuthenticationMethod;

/**
 * Simple Bean implementation of the authentication method.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class AuthenticationMethod implements IAuthenticationMethod, Serializable 
{
    /** method id */
    protected String _sID;
    /** serialVersionUID */
    private static final long serialVersionUID = 1349286804710185409L;
    
    /**
     * Creates the method object with empty items.
     *
     * If this constructor is used, the protected class variables should be set 
     * manualy.
     */
    protected AuthenticationMethod()
    {
        _sID = null;
    }
    
	/**
	 * Creates the method object.
     * 
     * The supplied <code>sId</code> and <code>sFriendlyName</code> may not be 
     * <code>null</code>.
     * 
	 * @param sID the ID of the authentication method
	 */
	public AuthenticationMethod(String sID)
    {
        _sID = sID;
	}

	/**
	 * Returns the method id.
	 * @return The ID
	 */
	public String getID()
    {
		return _sID;
	}

    /**
     * Returns the hashcode based on the method id.
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        return _sID.hashCode();        
    }
    
    /**
     * Verifies whether the supplied method is equal to this method.
     * 
     * Returns TRUE if the ID of the supplied method ID is equal to the ID of 
     * this method. 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object obj)
    {
        if (!(obj instanceof AuthenticationMethod))
            return false;
        
        AuthenticationMethod oAuthenticationMethod = (AuthenticationMethod)obj;
        
        return _sID.equals(oAuthenticationMethod._sID);
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        return "Authentication Method: " + _sID;
    }
}