/*
 * Asimba Server
 * 
 * Copyright (C) 2013 Asimba
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

import com.alfaariss.oa.engine.user.provisioning.ProvisioningUser;

/**
 * Base class for a user that is instantiated through provisioning
 * from a remote authentication source, like a remote SAML2 or ASelect
 * server
 * 
 * @author mdobrinic
 *
 */
public class RemoteProvisioningUser extends ProvisioningUser {
	/** For serialization */
	private static final long serialVersionUID = 736061208270016565L;

    /** The AuthenticationMethodId that instantiated the object */
    protected String _sPrimaryMethodId;
    
	/**
	 * Create new RemoteProvisioninUser instance
	 * @param sOrganization Organization of the user
	 * @param sUserId Id of the user
	 * @param bEnabled Whether the user is enabled or not
	 * @param sMethodId AuthenticationMethodId that authenticated the user
	 */
	public RemoteProvisioningUser(String sOrganization, String sUserId, boolean bEnabled, String sMethodId)
    {
        super(sOrganization, sUserId, true);

        _sPrimaryMethodId = sMethodId;
        
        // Register the Remote Authentication method that was used as enabled (historical fact)
        putRegistered(sMethodId, true);
    }
	
	public RemoteProvisioningUser(ProvisioningUser oProvisioningUser, String sMethodId)
	{
        super(oProvisioningUser);

        _sPrimaryMethodId = sMethodId;
        
        // Register the Remote Authentication method that was used as enabled (historical fact)
        putRegistered(sMethodId, true);
	}
}
