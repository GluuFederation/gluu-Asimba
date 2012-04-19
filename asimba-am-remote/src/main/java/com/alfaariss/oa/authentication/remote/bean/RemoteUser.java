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
package com.alfaariss.oa.authentication.remote.bean;

import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.user.AbstractUser;

/**
 * User object for users authenticated at a remote Server.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class RemoteUser extends AbstractUser
{
    private static final long serialVersionUID = -328516854068382110L;
    private String _sMethodID;

    /**
     * Creates the user object.
     *
     * @param sOrganization the user organization
     * @param sUserId The unique remote user ID.
     * @param sMethodID Method id
     */
    public RemoteUser(String sOrganization, String sUserId, String sMethodID)
    {
        super(sOrganization, sUserId, true);
        _sMethodID = sMethodID;
    }
    
    /**
     * Returns <code>method != null && method equals this.method</code>.
     * @see IUser#isAuthenticationRegistered(java.lang.String)
     */
    public boolean isAuthenticationRegistered(String method)
    {
        return (method != null && method.equals(_sMethodID));
    }

}
