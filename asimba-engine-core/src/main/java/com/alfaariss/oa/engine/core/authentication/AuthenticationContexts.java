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
package com.alfaariss.oa.engine.core.authentication;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.alfaariss.oa.api.authentication.IAuthenticationContext;
import com.alfaariss.oa.api.authentication.IAuthenticationContexts;

/**
 * Class to register Authentication Contexts for every performed Authentication 
 * Method
 * 
 * Created to be able to normalize authentiation properties as well as use
 * the actual properties (some of which may be AuthMethod-specific) in other 
 * parts of the authentication and authorization chain
 * 
 * @author mdobrinic
 *
 */
public class AuthenticationContexts implements IAuthenticationContexts {

	/** Generated version ID */
	private static final long serialVersionUID = -6452335212840593325L;

	/** Session/TGT Attributename for registering authentication method's performed context */
	public static final String ATTR_AUTHCONTEXTS = "authcontexts";

	
	private Map<String, IAuthenticationContext> _mAuthenticationContexts;

	public AuthenticationContexts() {
		_mAuthenticationContexts = new HashMap<String, IAuthenticationContext>();
	}

	@Override
	public boolean contains(String sAuthnMethod) {
		return _mAuthenticationContexts.containsKey(sAuthnMethod);
	}

	@Override
	public void setAuthenticationContext(String sAuthnMethod,
			IAuthenticationContext oAuthenticationContext) {
		_mAuthenticationContexts.put(sAuthnMethod, oAuthenticationContext);
	}

	@Override
	public IAuthenticationContext getAuthenticationContext(String sAuthnMethod) {
		return _mAuthenticationContexts.get(sAuthnMethod);
	}

	@Override
	public Set<String> getStoredAuthenticationMethods() {
		return Collections.unmodifiableSet(_mAuthenticationContexts.keySet());
	}
}
