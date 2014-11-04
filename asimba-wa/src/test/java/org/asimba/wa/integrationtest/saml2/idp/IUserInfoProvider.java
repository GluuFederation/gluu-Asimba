/*
 * Asimba - Serious Open Source SSO
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
package org.asimba.wa.integrationtest.saml2.idp;

import java.util.Map;

public interface IUserInfoProvider {

	public static final String SAML_NAMEIDFORMAT_UNSPECIFIED =
			"urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified";
	public static final String SAML_NAMEIDFORMAT_PERSISTENT =
			"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
	public static final String SAML_NAMEIDFORMAT_TRANSIENT =
			"urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
	
	public String getUserId(String format);
	public Map<String, String> getAttributes(); 
	
}
