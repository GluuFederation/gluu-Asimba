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
package com.alfaariss.oa.api.authorization;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.IManagebleItem;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;

/**
 * Interface to be implemented by all authorization actions.
 *
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public interface IAuthorizationAction extends IManagebleItem
{
    /**
     * Converts the result of the authorization method to a user event.
     *  
     * @param oSession The session object used for authentication.
     * @return user event
     * @throws OAException if perform fails
     */
    public UserEvent perform(ISession oSession) throws OAException;
    
    /**
     * Start the action.
     * @param oConfigurationManager the configuration manager used to retrieve 
     * the config from the supplied <code>Element</code>. 
     * @param eConfig The configuration section or <code>null</code> if no 
     * configuration is found.
     * @throws OAException if starting fails
     */
    public void start(IConfigurationManager oConfigurationManager
        , Element eConfig) throws OAException;
    
    /**
     * Stops the action.
     */
    public void stop();
}
