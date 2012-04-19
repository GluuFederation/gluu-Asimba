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
package com.alfaariss.oa.engine.core.authentication.factory;

import com.alfaariss.oa.engine.core.authentication.AuthenticationException;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;

/**
 * Interface for an authentication profile factory.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IAuthenticationProfileFactory
{

	/**
	 * Returns all profiles that can be used for the supplied requestor pool.
	 * @param sProfile The authentication profile id
	 * @return A set containing all authentication profiles or <code>null</code> 
     * if not exists
	 * @throws AuthenticationException
	 */
	public AuthenticationProfile getProfile(
        String sProfile) throws AuthenticationException;
}