/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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
package com.alfaariss.oa.engine.core.idp.storage;

import java.util.List;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * IDP Storage interface.
 * @author MHO
 * @author Alfa & Ariss
 * @param <IDP> IDP type.
 * @since 1.4
 */
public interface IIDPStorage<IDP extends IIDP>
{
    /**
     * Starts the object by reading it's configuration.
     * @param configManager The configuration manager.
     * @param config The configuration of this object.
     * @throws OAException If the configuration is invalid.
     */
    public void start(IConfigurationManager configManager, 
        Element config) throws OAException;
    
    /**
     * Stops the object.
     */
    public void stop();
    
    /**
     * Returns the ID of the storage. 
     * @return The ID of the storage.
     */
    public String getID();
    
    /**
     * Returns the IDP by it's ID.
     * @param id The ID of the IDP.
     * @return The specified IDP or NULL if not available.
     * @throws OAException If an internal error ocurres.
     */
    public IDP getIDP(String id) throws OAException;
    
    /**
     * Returns the IDP specified by the supplied ID where the ID has a specific type.
     * <br>
     * Tries to retrieve the first IDP that matches the supplied ID in one of 
     * the storages.
     * @param id The ID of the IDP.
     * @param type The type of ID that is supplied.
     * @return The IDP or <code>null</code> if none found.
     * @throws OAException If an internal error ocurres.
     */
    public IIDP getIDP(Object id, String type) throws OAException;
    
    /**
     * Returns all IDP's according the IIDP interface.
     * @return An unmodifiable list containing all IDP's.
     * @throws OAException If an internal error ocurres.
     */
    public List<IIDP> getAll() throws OAException;
    
    /**
     * Verified if the supplied ID corresponds to an IDP.
     * @param id The ID of the IDP.
     * @return TRUE if the IDP exists.
     * @throws OAException If an internal error ocurres.
     */
    public boolean exists(String id) throws OAException;
}
