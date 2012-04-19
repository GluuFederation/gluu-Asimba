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
package com.alfaariss.oa.engine.core.attribute.release.factory;
import com.alfaariss.oa.api.IOptional;
import com.alfaariss.oa.engine.core.attribute.AttributeException;
import com.alfaariss.oa.engine.core.attribute.release.IAttributeReleasePolicy;

/**
 * Interface for an attribute release policy factory.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IAttributeReleasePolicyFactory extends IOptional
{

	/**
	 * Returns the release policy by supplying a policy id.
	 * @param sPolicy the policy id
	 * @return the release policy or <code>null</code> if not exists
	 * @throws AttributeException if retrieval fails
	 */
	public IAttributeReleasePolicy getPolicy(String sPolicy) 
	    throws AttributeException;

}