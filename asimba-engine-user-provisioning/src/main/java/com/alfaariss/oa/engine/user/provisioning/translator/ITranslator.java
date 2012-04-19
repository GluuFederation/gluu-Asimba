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
package com.alfaariss.oa.engine.user.provisioning.translator;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.ProvisioningUser;
import com.alfaariss.oa.engine.user.provisioning.storage.StorageManager;
import com.alfaariss.oa.engine.user.provisioning.storage.internal.IInternalStorage;

/**
 * Interface for translator objects.
 * <br>
 * Translates a user from external storage to a user for the internal storage.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface ITranslator 
{
	/**
     * Starts the object.
	 * @param oConfigurationManager the configuration manager 
	 * @param eConfig the configuration section containing the configuration of this object
	 * @param oStorageManager the storage manager
	 * @param oInternalStorage the internal storage
	 * @throws UserException if starting fails
	 */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig, StorageManager oStorageManager, 
        IInternalStorage oInternalStorage) throws UserException;

	/**
     * Translate the user with the supplied user id
	 * @param sUserID the user id
	 * @return IUser the user
	 * @throws UserException if translating fails
	 */
	public ProvisioningUser translate(String sUserID) throws UserException;

    /** Stops the object*/
    public void stop();
}