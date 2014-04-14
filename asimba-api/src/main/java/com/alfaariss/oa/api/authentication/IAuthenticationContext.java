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
 * IAuthenticationContext describes an Authentication Context
 * 
 * It basically wraps around a list of key->value properties
 * 
 * Note: the values of properties MUST be Serializable, so they can be passed
 * around and stored
 * 
 * @author mdobrinic
 *
 */
public interface IAuthenticationContext extends Serializable {

	/**
	 * Set (overwrite or create) the value for a key
	 * @param key name of the property
	 * @param value value to set for the property
	 */
	public void set(String key, String value);
	
	/**
	 * Get the value for a key
	 * @param key name of the property
	 * @return value of the property
	 */
	public String get(String key);
	
	/**
	 * Return a set with all the keys in the AuthenticationContext
	 * @return set with all keys in the AuthenticationContext
	 */
	public Set<String> getKeys();
	
	/**
	 * Return whether a value for a key is set
	 * @param key key to look up
	 * @return
	 */
	public boolean contains(String key);
	
	/**
	 * Clear all the keys
	 */
	public void clear();
	
}
