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

/**
 * Basic configuration for building SAML Response
 * 
 * @author mdobrinic
 *
 */
public class BasicResponseContextProvider implements IResponseContextProvider {

	private boolean _wantsAssertionsSigned = true;	// default
	private boolean _signResponse = true;
	private boolean _signAssertion = true;
	
	
	public void setWantsAssertionsSigned(boolean wantsAssertionsSigned) {
		_wantsAssertionsSigned = wantsAssertionsSigned;
	}
	
	public boolean getWantsAssertionsSigned() {
		return _wantsAssertionsSigned;
	}
	
	public void setSignResponse(boolean signResponse) {
		_signResponse = signResponse;
	}
	
	public boolean getSignResponse() {
		return _signResponse;
	}
	
	public void setSignAssertion(boolean signAssertion) {
		_signAssertion = signAssertion;
	}
	
	public boolean getSignAssertion() {
		return _signAssertion;
	}
	

}
