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
package com.alfaariss.oa.engine.user.provisioning.storage.internal;

import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.ProvisioningUser;
import com.alfaariss.oa.engine.user.provisioning.storage.IStorage;

/**
 * Interface for internal storages.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IInternalStorage extends IStorage
{
    /**
     * Returns the user.
     * @param sOrganization organization id
     * @param id the user id
     * @return A user object
     * @throws UserException if the retrieval fails 
     */
    public ProvisioningUser getUser(String sOrganization, String id) throws UserException;

    /**
     * Adds the supplied user to the storage.
     * @param user the user object
     * @throws UserException 
     */
    public void add(ProvisioningUser user) throws UserException;
    
    /**
     * Updates the internal user with the supplied user.
     * @param user provisioning user object
     * @throws UserException if updating fails
     */
    public void update(ProvisioningUser user) throws UserException;
    
    /**
     * Removes the user with the supplied id from the storage.
     * @param id the user id
     * @throws UserException if remove fails
     */
    public void remove(String id) throws UserException;

}
