/*
 * Asimba Server
 * 
 * Copyright (C) 2013 Asimba
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
package org.asimba.engine.core.confederation;

import java.util.List;
import java.util.Map;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;


/**
 * A Confederation defines a remote federation that is trusted
 * by us, as a local (federation) identity provider 
 * 
 * @author mdobrinic
 */
public interface IConfederation {
	/**
	 * Argument for getIDPs to specify no particular requestor
	 */
	public static final String UNSPECIFIED_REQUESTOR = null;

	/**
	 * Argument to indicate no specific context
	 */
	public static final Map<String, String> NO_CONTEXT = null;
	

	/**
	 * Retrieve the ID of the confederation
	 * @return
	 */
	public String getID();

	
	/**
	 * Retrieve a list of all the services that are managed by the
	 * remote federation
	 * @param sIDP ID of the IDP for which the available services are
	 *   requested; can be null
	 * @param mContext optional extra filtering criteria for the provider
	 * 
	 * @return List of IRequestor instances, each defining a service
	 */
	public List<IRequestor> getSPs(String sIDP, Map<String, String> mContext)
			throws OAException;
	
	
	/**
	 * Retrieve a list of all the identity providers that are managed
	 * by the remote federation
	 * 
	 * @return List of IIDP instances, each defining an IDP
	 */
	public List<? extends IIDP> getIDPs(String sRequestor, Map<String, String> mContext)
			throws OAException;
}
