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
package com.alfaariss.oa.engine.user.provisioning.storage;

import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;

/**
 * Interface for storage managers.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IStorage
{
    /**
     * Starts the storage object.
     * @param oConfigurationManager the configuration manager 
     * @param eConfig the configuration section for this object
     * @throws UserException if starting fails
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws UserException;

    /**
     * Verifies if the supplied id exists in the storage.
     * @param sID the unique id
     * @return TRUE if the id exists
     * @throws UserException if verification fails
     */
    public boolean exists(String sID) throws UserException;
    
    /** Stops the object */
    public void stop();
}
