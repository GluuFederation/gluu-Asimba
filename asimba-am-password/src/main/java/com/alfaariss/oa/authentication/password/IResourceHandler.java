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
package com.alfaariss.oa.authentication.password;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Interface IResourceHandler. Resources must implement this interface.
 * 
 * @author BNE
 * @author Alfa & Ariss
 */
public interface IResourceHandler
{

    /**
     * Authenticate the user with the password.
     *
     * @param password The password
     * @param username The username
     * @return True if the authentication was successful.
     * @throws UserException
     * @throws OAException
     */
    public boolean authenticate(String password, String username) throws UserException, OAException;

    /**
     * Initialize.
     * 
     * @param manager The configuration manager.
     * @param eResourceSection The start of the config.
     * @throws OAException
     */
    public void init(IConfigurationManager manager, Element eResourceSection) throws OAException;

    /**
     * Get the realm (name) of this resource.
     * @return The realm.
     * 
     */
    public String getResourceRealm();
}
