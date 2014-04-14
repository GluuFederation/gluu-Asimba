/*
 * Asimba Server
 * 
 * Copyright (C) 2014 Asimba
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

import java.io.Serializable;
import java.util.Set;

/**
 * Interface that specifies how IAuthenticationContexts are registered
 * 
 * IAuthenticationContexts is a template for a class that is passed around in a Session or TGT.
 * 
 * The IAuthenticationContexts registers instances of IAuthenticationContext with a 
 * name of an Authentication Method
 *  
 * @author mdobrinic
 *
 */
public interface IAuthenticationContexts extends Serializable {
	
	/**
	 * Establish whether there exists an authentication context for the provided
	 * Authentication Method
	 * @param sAuthMethod
	 * @return true if exists, false if not
	 */
	public boolean contains(String sAuthnMethod);
	
	
	/**
	 * Updates or sets the authentication context for the provided Authentication Method
	 * @param sAuthnMethod
	 * @param oAuthenticationContext
	 */
	public void setAuthenticationContext(String sAuthnMethod, IAuthenticationContext oAuthenticationContext);
	
	
	/**
	 * Retrieves the authentication context for a provided Authentication Method
	 * @param sAuthnMethod
	 * @return
	 */
	public IAuthenticationContext getAuthenticationContext(String sAuthnMethod);
	
	
	/**
	 * Retrieve a list of Authentication Method's for which an authentication context
	 * is registered
	 * @return
	 */
	public Set<String> getStoredAuthenticationMethods(); 
}
