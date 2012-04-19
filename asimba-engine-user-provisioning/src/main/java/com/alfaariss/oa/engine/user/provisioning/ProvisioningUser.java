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
package com.alfaariss.oa.engine.user.provisioning;
import java.util.HashMap;
import java.util.Set;

import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.user.AbstractUser;

/**
 * The provisioning user class.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ProvisioningUser extends AbstractUser 
{
    private static final long serialVersionUID = -9019776671693257312L;
    private HashMap<String, Boolean> _mapRegistered;
    
    /**
     * Creates the object.
     * @param sOrganization The organization of the user
     * @param sUserId the user id
     * @param bEnabled TRUE if account is enabled.
     */
    public ProvisioningUser(String sOrganization, String sUserId, boolean bEnabled)
    {
        super(sOrganization, sUserId, bEnabled);
        _mapRegistered = new HashMap<String, Boolean>();
    }
    
    /**
     * Add or overwrites the Map with registered authentication methods.
     * @param sAuthenticationMethod The authentication method Id
     * @param bRegistered <code>true</code> if the user is registered 
     * for the authentication method
     */
    public void putRegistered(String sAuthenticationMethod, boolean bRegistered)
    {
        _mapRegistered.put(sAuthenticationMethod, bRegistered);
    }

    /**
     * Returns TRUE if the user is registered for the supplied authentication 
     * method.
     * @see IUser#isAuthenticationRegistered(java.lang.String)
     */
    public boolean isAuthenticationRegistered(String method)
    {
        Boolean boolRegistered = _mapRegistered.get(method);
        if (boolRegistered == null)
            return false;
        
        return boolRegistered;
    }


    /**
     * Returns all authentication method id's.
     * @return a set with authentication methods
     */
    public Set<String> getAuthenticationMethods()
    {
        return _mapRegistered.keySet();
    }
}