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
 */package com.alfaariss.oa.engine.core.authentication;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.alfaariss.oa.api.authentication.IAuthenticationContext;

/**
 * Class to register key-value properties for an Authentication Context
 * 
 * @author mdobrinic
 *
 */
public class AuthenticationContext implements IAuthenticationContext, Serializable {
	/** Generated Version ID */
	private static final long serialVersionUID = 8800195465850632139L;

	/** String value: Issuer of the authenticated identity or assertion */
	public static final String ATTR_ISSUER = "issuer";
	/** Space Separated String value: Audience of the authenticated identity or assertion */
	public static final String ATTR_AUDIENCE = "audience";
	/** XML formatted timestamp string: time after which the assertion expires */
	public static final String ATTR_EXPIRATION = "expiration";
	/** XML formatted timestamp string: time when authentication took place */
	public static final String ATTR_AUTHENTICATION_TIME = "authentication_time";
	/** String: random and unique nonce that is part of the issued assertion or authenticated identity (replay prevention) */
	public static final String ATTR_NONCE = "nonce";
	/** String: name of the authentication context classref that was performed to authenticate the subject */
	public static final String ATTR_AUTHNCONTEXT_CLASSREF = "authncontext_classref";
	/** Space Separated String: reference to the authentication methods that were used to authenticate the subject */
	public static final String ATTR_AUTHMETHOD_REFERENCE = "authmethod_reference";
	/** String: name of the party for which the assertion was meant to be consumed */
	public static final String ATTR_AUTHORIZED_PARTY = "authorized_party";
	
	
	private Map<String, String> _mAuthenticationProperties;
	
	
	public AuthenticationContext() {
		_mAuthenticationProperties = new HashMap<String, String>();
	}
	
	@Override
	public void set(String key, String value) {
		_mAuthenticationProperties.put(key, value);
	}

	@Override
	public String get(String key) {
		return _mAuthenticationProperties.get(key);
	}

	@Override
	public Set<String> getKeys() {
		return Collections.unmodifiableSet(_mAuthenticationProperties.keySet());
	}

	@Override
	public boolean contains(String key) {
		return _mAuthenticationProperties.containsKey(key);
	}

	@Override
	public void clear() {
		_mAuthenticationProperties.clear();
	}
	
}
