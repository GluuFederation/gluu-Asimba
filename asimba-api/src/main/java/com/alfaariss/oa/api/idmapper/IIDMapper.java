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
package com.alfaariss.oa.api.idmapper;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * User ID mapper interface.
 * <br>
 * Can be used to map the OpenASelect user ID to the ID needed by an 
 * authentication method.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IIDMapper
{
    /**
     * Starting the mapper.
     *
     * @param oConfigManager configuration manager
     * @param eConfig mapper config section
     * @throws OAException if creation fails
     */
    public void start(IConfigurationManager oConfigManager, Element eConfig) throws OAException;
    
    /**
     * Returns the mapped user ID.
     * @param sUserID user ID to be mapped
     * @return mapped user ID
     * @throws OAException if mapping fails
     */
    public String map(String sUserID) throws OAException;
    
    /**
     * Returns the real user ID.
     * @param sMappedUserID
     * @return remapped user ID
     * @throws OAException if remapping fails
     */
    public String remap(String sMappedUserID) throws OAException;
    /**
     * Stops the mapper. 
     */
    public void stop();
}
