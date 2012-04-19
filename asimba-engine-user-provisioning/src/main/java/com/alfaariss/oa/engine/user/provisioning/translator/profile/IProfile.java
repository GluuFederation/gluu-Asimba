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
package com.alfaariss.oa.engine.user.provisioning.translator.profile;

import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.ProvisioningUser;
import com.alfaariss.oa.engine.user.provisioning.storage.external.IExternalStorage;

/**
 * Interface for a Profile.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IProfile
{
    /**
     * Starts the object.
     * @param oConfigurationManager the configuration manager 
     * @param eConfig the configuration section that contains the configuration 
     * for this object.
     * @param oExternalStorage the external storage
     * @throws UserException if starting fails.
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig, IExternalStorage oExternalStorage) throws UserException;

    /**
     * Returns the user object based on his existence in the external storage.
     * 
     * @param sOrganization the user organization id
     * @param id the user id
     * @return provisioning user object
     * @throws UserException if user retrieval fails.
     */
    public ProvisioningUser getUser(
        String sOrganization, String id) throws UserException;
    
    /**
     * Stops the profile. 
     */
    public void stop();

}
