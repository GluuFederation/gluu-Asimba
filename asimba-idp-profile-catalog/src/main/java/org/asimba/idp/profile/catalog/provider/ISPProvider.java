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
package org.asimba.idp.profile.catalog.provider;

import java.util.List;

import org.joda.time.DateTime;

import com.alfaariss.oa.api.requestor.IRequestor;

public interface ISPProvider extends IProvider {

	/**
	 * Return all the SPs that the SPProvider can provide
	 * Use Asimba IRequestor instances 
	 * @return
	 */
	public List<IRequestor> getSPs();

	
	/**
	 * Return the timestamp of the last modification that was known
	 * to either the Provider or any of its contained SPs
	 * 
	 * @return Timestamp when Provider was last modified, or null if
	 * this was unknown
	 */
	public DateTime getDateLastModified();

}
