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
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

 
/**
 * This class defines the interface for all password handlers.
 * @author LVR
 * @author JVG
 * @author Alfa & Ariss
 *
 */
public interface IPasswordHandler 
{
    /** Charset is UTF-8 */
    public final static String CHARSET = "UTF-8";    
    
    /**
     * Authenticate method. 
     * 
     * DD User not found in password back-end results in {@link UserEvent#AUTHN_METHOD_NOT_SUPPORTED}. 
     * @param sUserName The user name. 
     * @param sPassword The password. 
     * @return true if authenticated. 
     * @throws OAException if an internal error occurs.
     * @throws UserException if a user authentication error occurs.
     *
     */
    public boolean authenticate(
        String sUserName, String sPassword) throws OAException, UserException;

    /**
     * Start the handler.
     * @param oConfigurationManager the configuration manager used to retrieve
     * the config from the supplied <code>Element</code>.
     * @param eConfig The configuration section or <code>null</code> if no 
     * configuration is found.
     * @throws OAException
     */
    public void start(IConfigurationManager oConfigurationManager
        , Element eConfig) throws OAException;
    
    /**
     * Stops the handler.
     */
    public void stop();
}
