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
package org.asimba.utility.profile;

/**
 * Generic support for profile implementations
 * 
 * @author mdobrinic
 *
 */
public class ProfileUtils {

	/**
	 * Establish the sub-request name from the URI<br/>
	 * Example:<br/>
	 * When the request was for URI "/context/profiles/oauth2/authorize/i=abc?p=123", this will
	 * strip off the prefix /context/profiles/oauth2 and return the name of the 
	 * endpoint "authorize/i=abc?p=123"; if the prefix could not be stripped off,
	 * null is returned.
	 * @param sContext Name of the deployed Servlet Context, i.e. '/asimba-wa' (first element)
	 * @param sProfile Name of the profile, i.e. 'oauth2' (third element)
	 * @param sRequestURI URI to process
	 * @return Name of the sub-path, or null if name could not be established
	 */
	public static String endpointFromURI(String sContext, String sProfile, 
			String sRequestURI) {
		if (sRequestURI.length() == 0) return null;
		if (sRequestURI.length() < (sContext.length()+1)) return null;
		
		// First, split off our context (i.e. "/asimba-wa")
		String s = sRequestURI.substring(sContext.length());
		
		// Next, split off "/profiles"
		if (s.length() < ("/profiles".length()+1)) return null;
		s = s.substring("/profiles".length());
		
		// now remove OAuth AuthorizationServer identifier
		if (! s.startsWith("/"+sProfile)) {
			return null;
		}
		
		if (s.length() < (sProfile.length()+2)) return null;
		s = s.substring(sProfile.length()+2);	// also remove trailing "/" ..
		
		return s;
	}
	
}
