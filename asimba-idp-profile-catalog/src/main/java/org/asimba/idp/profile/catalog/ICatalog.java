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
package org.asimba.idp.profile.catalog;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;

public interface ICatalog extends IComponent {

	/**
	 * Retrieve the ID of the catalog instance
	 * @return
	 */
	public String getID();
	
	
	/**
	 * Returns the list of IDPs that are considered for publication by 
	 * this catalog
	 * @param oRequest The context with which to establish the IDPs
	 * @return List of IIDP instances
	 */
	public List<IIDP> getIDPs(HttpServletRequest oRequest);
	
	
	/**
	 * Returns the list of Requestors (SPs) that are considered for 
	 * publication by this catalog
	 * @param oRequest The context with which to establish the Requestors
	 * @return List of IRequestor instances
	 */
	public List<IRequestor> getRequestors(HttpServletRequest oRequest);
	
	
	/**
	 * Handle the catalog request
	 * @param oRequest
	 * @param oResponse
	 * @throws OAException
	 */
	public void service(HttpServletRequest oRequest, HttpServletResponse oResponse)
		throws OAException;
	
}
