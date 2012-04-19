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
package com.alfaariss.oa.api.user;
import java.io.Serializable;

import com.alfaariss.oa.api.attribute.IAttributes;

/**
 * An interface for a standard OA user.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public interface IUser extends Serializable
{
	/**
	 * Retrieve the user ID.
	 * @return String The user identification.
	 */
	public String getID();

	/**
	 * Is this user OA enabled?.
	 * @return boolean <code>true</code> if this user is enabled.
	 */
	public boolean isEnabled();

	/**
	 * Is this user enabled for the authentication method?
	 * @param method The authentication method id.
	 * @return <code>true</code> if the user is 
	 * enabled for the given authentication method.
     * @since 1.2
	 */
	public boolean isAuthenticationRegistered(String method);

	/**
	 * Retrieve the user attributes.
	 * @return IAttributes The user its attributes.
	 */
	public IAttributes getAttributes();

	/**
     * Update the user attributes.
	 * @param oAttributes the new attributes.
	 */
	public void setAttributes(IAttributes oAttributes);

    /**
     * Returns the users remote organization.
     * @return the organization of the user
     */
    public String getOrganization();
}