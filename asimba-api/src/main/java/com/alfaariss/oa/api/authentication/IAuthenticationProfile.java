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
package com.alfaariss.oa.api.authentication;

import java.util.List;

import com.alfaariss.oa.api.IManagebleItem;

/**
 * Authentication profile interface. 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IAuthenticationProfile 
	extends IManagebleItem, Comparable<IAuthenticationProfile> 
{

    /**
     * Adds an authentication method at the end of the list.
     * @param oAuthenticationMethod The method that must be added
     */
    public void addAuthenticationMethod(IAuthenticationMethod oAuthenticationMethod);
    
	/**
     * Returns the list of authentication methods.
	 * @return the list of authentication methods
	 */
	public List<IAuthenticationMethod> getAuthenticationMethods();
	
	/**
	 * Check if this profile contains a specific authentication method.
	 * 
	 * @param method The authentication method.
	 * @return <code>true</code> is this profile contains the given method.
	 */
	public boolean containsMethod(IAuthenticationMethod method);
}