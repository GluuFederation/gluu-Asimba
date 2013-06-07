/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.aselect;

import com.alfaariss.oa.authentication.remote.bean.RemoteProvisioningUser;
import com.alfaariss.oa.engine.user.provisioning.ProvisioningUser;

/**
 * Remote A-Select user
 * 
 * Based on RemoteProvisioningUser, as the user can be provisioned through
 * the provided authentication and attribute context of the remote IDP
 *
 * @author mdobrinic
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class ASelectRemoteUser extends RemoteProvisioningUser
{
    /** serialVersionUID */
    private static final long serialVersionUID = -7084900438659203979L;
    
    private String _sCredentials;
    
    /**
     * Creates the user object
     * 
     * By default, the user account is enabled.
     *
     * @param organization the user organization
     * @param userId The unique remote user ID
     * @param methodID Method id
     * @param credentials A-Select credentials
     */
    public ASelectRemoteUser (String organization, String userId, String methodID, 
    		String credentials) 
    {
        super(organization, userId, true, methodID);
        _sCredentials = credentials;
    }
    
    
    /**
     * Constructor that initializes from a ProvisioningUser instance
     */
    public ASelectRemoteUser(ProvisioningUser oProvisioningUser, String sMethodId, 
    		String sCredentials) 
    {
    	super(oProvisioningUser, sMethodId);
    	_sCredentials = sCredentials;
    }
    
    
    /**
     * Returns the A-Select credentials retrieved during authentication from the remote organization. 
     * @return A-Select credentials
     */
    public String getCredentials()
    {
        return _sCredentials;
    }
}
