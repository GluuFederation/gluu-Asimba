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
package com.alfaariss.oa.engine.core.user.factory;
import com.alfaariss.oa.api.IOptional;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.user.UserException;

/**
 * An interface for user factories.
 *
 * Implementations of this interface can be used to retrieve users.
 * These factories should be implemented using the abstract factory 
 * design pattern. 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IUserFactory extends IOptional
{

	/**
	 * Returns a user object with specific OA user information.
	 * @param sID The user ID.
	 * @return An IUser object
	 * @throws UserException 
	 */
	public IUser getUser(String sID) throws UserException;

}