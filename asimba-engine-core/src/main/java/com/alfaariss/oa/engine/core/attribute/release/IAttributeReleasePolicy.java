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
package com.alfaariss.oa.engine.core.attribute.release;

import com.alfaariss.oa.api.IManagebleItem;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.engine.core.attribute.AttributeException;

/**
 * An interface for Attribute Release Policies.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public interface IAttributeReleasePolicy extends IManagebleItem
{
    /**
	 * Applies the attribute release policy.
     * 
	 * @param oAttributes the attributes object that will be changed according 
     * to the policy
     * @return A new attributes object containing the attributes where the policy has been applied to.
     * @throws AttributeException if applying fails
	 */
	public IAttributes apply(IAttributes oAttributes) throws AttributeException;

}