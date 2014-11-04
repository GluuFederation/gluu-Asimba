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
package org.asimba.wa.integrationtest.saml;

/**
 * Report failure
 * @author mdobrinic
 *
 */
public class SAMLFailException extends Exception {
	
	/** version */
	private static final long serialVersionUID = 9083779435689457895L;

	public SAMLFailException()
	{
	}
	
	public SAMLFailException(String msg)
	{
		super(msg);
	}
	
	public SAMLFailException(Throwable t)
	{
		super(t);
	}
	
	public SAMLFailException(String msg, Throwable t)
	{
		super(msg,t);
	}
}
